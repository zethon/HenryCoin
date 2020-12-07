#include <charconv>
#include <cassert>

#include <nlohmann/json.hpp>

#include "index_html.h"

#include "utils.h"
#include "core.h"
#include "ComputerUUID.h"
#include "MinerApp.h"

namespace nl = nlohmann;

namespace ash
{

#ifdef _RELEASE
constexpr auto BLOCK_GENERATION_INTERVAL = 10u * 60u; // in seconds
constexpr auto DIFFICULTY_ADJUSTMENT_INTERVAL = 25u; // in blocks
#else
constexpr auto BLOCK_GENERATION_INTERVAL = 60u; // in seconds
constexpr auto DIFFICULTY_ADJUSTMENT_INTERVAL = 10; // in blocks
#endif

MinerApp::MinerApp(SettingsPtr settings)
    : _settings{ std::move(settings) },
      _httpThread{},
      _mineThread{},
      _logger(ash::initializeLogger("MinerApp"))
{
    const std::string dbfolder = _settings->value("database.folder", "");

    utils::ComputerUUID uuid;
    uuid.setCustomData(dbfolder);
    _uuid = uuid.getUUID();
    
    _logger->debug("current miner uuid is {}", _uuid);

    std::uint32_t difficulty = _settings->value("chain.difficulty", 5u);

    _logger->info("current difficulty set to {}", difficulty);
    _logger->debug("target block generation interval is {} seconds", BLOCK_GENERATION_INTERVAL);
    _logger->debug("difficulty adjustment interval is every {} blocks", DIFFICULTY_ADJUSTMENT_INTERVAL);

    initRest();
    initWebSocket();
    initPeers();

    _miner.setDifficulty(difficulty);

    _blockchain = std::make_unique<Blockchain>();

    _database = std::make_unique<ChainDatabase>(dbfolder);
    _database->initialize(*_blockchain);

    _peers.broadcast(R"({"message":"summary"})");
}

MinerApp::~MinerApp()
{
    if (_mineThread.joinable())
    {
        _mineThread.join();
    }

    if (_httpThread.joinable())
    {
        _httpServer.stop();
        _httpThread.join();
    }
}

void MinerApp::printIndex(HttpResponsePtr response)
{
    utils::Dictionary dict;
    dict["%app-title%"] = APP_NAME_LONG;
    dict["%app-domain%"] = APP_DOMAIN;
    dict["%app-github%"] = GITHUB_PAGE;
    dict["%app-copyright%"] = COPYRIGHT;
    dict["%build-date%"] = BUILDTIMESTAMP;
    dict["%build-version%"] = VERSION;
    dict["%chain-size%"] = std::to_string(_blockchain->size() - 1);
    dict["%chain-diff%"] = std::to_string(_miner.difficulty());
    dict["%chain-cumdiff%"] = std::to_string(_blockchain->cumDifficulty());
    dict["%mining-status%"] = (_miningDone ? "stopped" : "started");
    dict["%mining-uuid%"] = _uuid;
    dict["%rest-port%"] 
        = std::to_string(_settings->value("rest.port", HTTPServerPortDefault));

    std::stringstream out;
    out << utils::DoDictionary(index_html, dict);
    response->write(out);
}

void MinerApp::initRest()
{
    _httpServer.config.port = _settings->value("rest.port", HTTPServerPortDefault);
    _httpServer.resource["^/$"]["GET"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request) 
        {
            this->printIndex(response);
        };

    _httpServer.resource["^/block-idx/([0-9]+)$"]["GET"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request)
        {
            const auto indexStr = request->path_match[1].str();
            int index = 0;
            auto result = 
                std::from_chars(indexStr.data(), indexStr.data() + indexStr.size(), index);

            std::stringstream ss;
            if (result.ec != std::errc() || index >= _blockchain->size())
            {
                ss << R"xx(<html><body><h2 stye="color:red">Invalid Block</h2></body></html>)xx";
            }
            else
            {
                nl::json json = _blockchain->getBlockByIndex(index);
                ss << "<pre>" << json.dump(4) << "</pre>";
                ss << "<br/>";
                if (index > 0) ss << "<a href='/block-idx/" << (index - 1) << "'>prev</a>&nbsp;";
                ss << "current: " << index;
                if (index < _blockchain->size()) ss << "&nbsp;<a href='/block-idx/" << (index + 1) << "'>next</a>&nbsp;";
            }
            
            response->write(ss);
        };

    _httpServer.resource["^/shutdown$"]["POST"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request) 
        {
            _logger->debug("shutdown request from {}", 
                request->remote_endpoint().address().to_string());

            response->write(SimpleWeb::StatusCode::success_ok, "OK");
            this->signalExit();
        };

    _httpServer.resource["^/stopMining$"]["POST"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request) 
        {
            _logger->debug("stopMining request from {}", 
                request->remote_endpoint().address().to_string());

            if (!this->_miningDone)
            {
                this->stopMining();
                if (this->_mineThread.joinable())
                {
                    this->_mineThread.join();
                }
                response->write(SimpleWeb::StatusCode::success_ok, "OK");
            }
            else
            {
                response->write(SimpleWeb::StatusCode::client_error_bad_request);
            }
        };

    _httpServer.resource["^/startMining$"]["POST"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request) 
        {
            _logger->trace("startMining request from {}", 
                request->remote_endpoint().address().to_string());

            if (this->_miningDone)
            {
                this->_miningDone = false;
                this->_mineThread = std::thread(&MinerApp::runMineThread, this);
                response->write(SimpleWeb::StatusCode::success_ok, "OK");
            }
            else
            {
                response->write(SimpleWeb::StatusCode::client_error_bad_request);
            }
        };

    _httpServer.resource["^/summary$"]["GET"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request)
        {
            nl::json jresponse;
            jresponse["blocks"].push_back(_blockchain->back());
            jresponse["cumdiff"] = _blockchain->cumDifficulty();
            jresponse["difficulty"] = _miner.difficulty();

            if (!this->_miningDone)
            {
                jresponse["status"] = fmt::format("mining block #{}",
                    this->_blockchain->size());
            }
            else
            {
                jresponse["status"] = "stopped";
            }

            response->write(jresponse.dump());
        };

    _httpServer.resource["^/block/([0-9]+)$"]["GET"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request) 
        {
            const auto indexStr = request->path_match[1].str();
            int blockIndex = 0;
            auto result = 
                std::from_chars(indexStr.data(), indexStr.data() + indexStr.size(), blockIndex);

            if (result.ec == std::errc::invalid_argument
                || blockIndex >= _blockchain->size())
            {
                response->write(SimpleWeb::StatusCode::client_error_bad_request);
                return;
            }

            nl::json json = _blockchain->at(blockIndex);
            response->write(json.dump());
        };

    _httpServer.resource["^/blocks/last/([0-9]+)$"]["GET"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request) 
        {
            const auto indexStr = request->path_match[1].str();
            int startingIdx = 0;
            auto result = 
                std::from_chars(indexStr.data(), indexStr.data() + indexStr.size(), startingIdx);

            if (result.ec == std::errc::invalid_argument)
            {
                return;
            }

            nl::json json;
            startingIdx = std::max(0ul, _blockchain->size() - startingIdx);
            for (auto idx = startingIdx; idx < _blockchain->size(); idx++)
            {
                json["blocks"].push_back(_blockchain->at(idx));
            }
            response->write(json.dump());
        };

    _httpServer.resource["^/addPeer/((?:[0-9]{1,3}\\.){3}[0-9]{1,3})$"]["GET"] = 
        [this](std::shared_ptr<HttpResponse> response, std::shared_ptr<HttpRequest> request)
        {
            response->write("<h1>peer added</h1>");
        };
}

void MinerApp::initWebSocket()
{
    auto port = _settings->value("websocket.port", WebSocketServerPorDefault);
    _peers.initWebSocketServer(port);

    _peers.onChainRequest.connect(
        [this](WsServerConnPtr connection, const std::string& message)
        {
            this->dispatchRequest(connection, message);
        });

    _peers.onChainResponse.connect(
        [this](WsClientConnPtr connection, const std::string& response)
        {
            this->handleResponse(connection, response);
        });
}

void MinerApp::initPeers()
{
    const std::string peersfile = _settings->value("peers.file", "");
    if (peersfile.size() == 0) return;
    _peers.loadPeers(peersfile);
    _peers.connectAll(
        [](WsClientConnPtr conn)
        {
            conn->send(R"({"message":"summary"})");
        });
}

void MinerApp::run()
{
    _httpThread = std::thread(
        [this]()
        {
            _logger->debug("http server listening on port {}", _httpServer.config.port);
            _httpServer.start();
        });

    if (_settings->value("mining.autostart", false))
    {
        _mineThread = std::thread(&MinerApp::runMineThread, this);
    }
    else
    {
        _miningDone = true;
    }
    
    if (_settings->value("rest.autoload", false))
    {
        const auto address = _httpServer.config.address.empty() ? 
            "localhost" : _httpServer.config.address;

        const auto localUrl = fmt::format("http://{}:{}",
            address, _httpServer.config.port);
        utils::openBrowser(localUrl);
    }

    while (!_done)
    {
        std::this_thread::yield();
    }
}

void MinerApp::runMineThread()
{
    auto blockAdjustmentCount = 0u;
    ash::CumulativeMovingAverage<std::uint64_t> avg;
    std::uint64_t index = 0;

    while (!_miningDone && !_done)
    {
        {
            std::lock_guard<std::mutex> lock{_chainMutex};
            index = _blockchain->size();
        }
    
        _logger->debug("mining block {} with difficulty {}", 
            index, _miner.difficulty());

        auto prevTime = static_cast<std::uint64_t>(_blockchain->back().time());

        const std::string data = fmt::format(":coinbase{}", index);
        auto result = _miner.mineBlock(index, data, _blockchain->back().hash());

        if (std::get<0>(result) == Miner::ABORT)
        {
            _logger->debug("mining block {} was aborted", index);
            continue;
        }

        auto& newblock = std::get<1>(result);
        newblock.setMiner(_uuid);

        // append the block to the chain
        if (!_blockchain->addNewBlock(newblock))
        {
            _logger->error("could not add new block #{} to blockchain, stopping mining", newblock.index());
            _miningDone = true;
            break;
        }

        // write the block to the database
        _database->write(newblock);

        _logger->info("successfully mined bock {}", index);

        // adjust difficulty if needed
        if (blockAdjustmentCount > DIFFICULTY_ADJUSTMENT_INTERVAL)
        {
            auto difficulty = _miner.difficulty();
            auto avgTime = avg.value();
            if (avgTime < (BLOCK_GENERATION_INTERVAL / 2.0f))
            {
                _logger->info("increasing difficulty from {} to {}", difficulty++, difficulty);
                _miner.setDifficulty(difficulty);
            }
            else if (avgTime > (BLOCK_GENERATION_INTERVAL * 2))
            {
                _logger->info("decreasing difficulty from {} to {}", difficulty--, difficulty);
                _miner.setDifficulty(difficulty);
            }
            else
            {
                _logger->debug("no difficulty adjustment required");
            }

            blockAdjustmentCount = 0;
            avg.reset();
        }
        else
        {
            avg.addValue(_blockchain->back().time() - prevTime);
            blockAdjustmentCount++;
        }

        // update our blockchain
        syncBlockchain();

        // request an update from the network
        _peers.broadcast(R"({"message":"summary"})");
    }
}

// the blockchain is synced at startup and
// after each block is mined
void MinerApp::syncBlockchain()
{
    if (std::lock_guard<std::mutex>{_chainMutex}; 
        _tempchain)
    {
        // we're replacing the full chaing
        if (_tempchain->front().index() == 0)
        {
            _blockchain.swap(_tempchain);
            _database->reset();
            _database->writeChain(*_blockchain);
        }
        else if (_tempchain->front().index() < _blockchain->back().index())
        {
            auto startIdx = _tempchain->front().index();
            _blockchain->resize(startIdx);
            for (const auto& block : *_tempchain)
            {
                // add up until a point of failure (if there
                // is one)
                if (!_blockchain->addNewBlock(block))
                {
                    _logger->warn("failed to add block while updating chain at index");
                }
            }

            _database->reset();
            _database->writeChain(*_blockchain);
        }
        else if (_tempchain->front().index() == _blockchain->back().index() + 1)
        {
            for (const auto& block : *_tempchain)
            {
                if (_blockchain->addNewBlock(block))
                {
                    _database->write(block);
                }
            }
        }
        else
        {
            _logger->warn("temp chain is too far ahead with blocks {}-{} and local chain {}-{}",
                _tempchain->front().index(), _tempchain->back().index(),
                _blockchain->front().index(), _blockchain->back().index());
        }

        _tempchain.reset();
    }
}

void MinerApp::dispatchRequest(WsServerConnPtr connection, std::string_view rawmsg)
{
    nl::json json = nl::json::parse(rawmsg, nullptr, false);
    if (json.is_discarded() || !json.contains("message"))
    {
        _logger->warn("malformed ws:/chain request on connection {}", 
            static_cast<void*>(connection.get()));

        nl::json response = R"({ "error": "malformed request" })";
        connection->send(response.dump());
        return;
    }

    const auto message = json["message"].get<std::string>();

    _logger->debug("ws:/chain received request on connection {}: {}", 
        static_cast<void*>(connection.get()), message);

    std::stringstream response;

    nl::json jresponse;
    jresponse["message"] = message;

    if (message == "summary")
    {
        jresponse["blocks"].push_back(_blockchain->front());
        jresponse["blocks"].push_back(_blockchain->back());
        jresponse["cumdiff"] = _blockchain->cumDifficulty();
    }
    else if (message == "chain")
    {
        if (!json.contains("id1") && !json.contains("id2"))
        {
            jresponse["blocks"] = *(this->_blockchain);
        }
        else if (!json["id1"].is_number())
        {
            jresponse["error"] = "invalid 'id1' value";
        }
        else if (!json["id2"].is_number())
        {
            jresponse["error"] = "invalid 'id2' value";
        }
        else
        {
            auto id1 = json["id1"].get<std::uint64_t>();
            auto id2 = json["id2"].get<std::uint64_t>();

            auto startIt = std::find_if(_blockchain->begin(), _blockchain->end(),
                [id1](const Block& block)
                {
                    return block.index() == id1;
                });

            if (startIt == _blockchain->end())
            {
                jresponse["error"] = "could not find id1 in chain";
            }
            else
            {
                for (auto currentIt = startIt; 
                    currentIt != _blockchain->end() && currentIt->index() <= id2; currentIt++)
                {
                    jresponse["blocks"].push_back(*currentIt);
                }
            }
        }
    }
    else
    {
        jresponse["error"] = fmt::format("unknown message '{}'", message);
    }

    response << jresponse.dump();
    connection->send(response.str());
}

void MinerApp::handleResponse(WsClientConnPtr connection, std::string_view rawmsg)
{
    nl::json json = nl::json::parse(rawmsg, nullptr, false);
    if (json.is_discarded() || !json.contains("message"))
    {
        _logger->warn("malformed wc:/chain response on connection {}", 
            static_cast<void*>(connection.get()));

        return;
    }

    const auto message = json["message"].get<std::string>();

    _logger->trace("wsc:/chain received response on connection {}, message='{}'", 
        static_cast<void*>(connection.get()), message);

    if (message == "summary")
    {
        if (!json.contains("blocks")
            || !json["blocks"].is_array()
            || json["blocks"].size() != 2)
        {
            _logger->warn("malformed ws:/chain 'latest' response on connection {}", 
                static_cast<void*>(connection.get()));
            return;
        }

        const auto& remote_gen = json["blocks"].at(0).get<ash::Block>();
        const auto& remote_last = json["blocks"].at(1).get<ash::Block>();
        
        // TODO: we're using the 'summary' command to determine
        // if we need to replace/update the chain, but we only
        // do those checks in 'summary'. We should do the thing
        // in the 'chain' command.
        const auto& genesis = _tempchain ? _tempchain->front() : _blockchain->front();
        const auto& lastblock = _tempchain ? _tempchain->back() : _blockchain->back();

        if (genesis != remote_gen)
        {
            _logger->warn("wsc:/chain 'summary' returned unknown chain on connection {}", 
                static_cast<void*>(connection.get()));

            if (_settings->value("chain.reset.enable", false))
            {
                _logger->info("requesting full remote chain");
                connection->send(R"({"message":"chain"})");
            }
        }
        else if (lastblock.index() < remote_last.index())
        {
            auto startIdx = lastblock.index() + 1;
            auto stopIdx = remote_last.index();

            _logger->info("'summary' returned larger chain on connection {}, requesting blocks {}-{}", 
                static_cast<void*>(connection.get()), startIdx, stopIdx);

            const auto msg = fmt::format(R"({{ "message":"chain","id1":{},"id2":{} }})",startIdx, stopIdx);
            connection->send(msg);
        }
        else
        {
            _logger->info("local blockchain up to date with connection {}",
                static_cast<void*>(connection.get()));
        }
    }
    else if (message == "chain")
    {
        if (const auto tempchain = json["blocks"].get<ash::Blockchain>();
                tempchain.size() <= 0 || !tempchain.isValidChain())
        {
            _logger->info("received invalid chain from connection {}", 
                static_cast<void*>(connection.get()));

            return;
        }
        else
        {
            std::lock_guard<std::mutex> lock(_chainMutex);
            handleChainResponse(connection, tempchain);
        }        
    }

    if (this->_miningDone)
    {
        syncBlockchain();
    }
}

void MinerApp::handleChainResponse(WsClientConnPtr connection, const Blockchain& tempchain)
{
    if (tempchain.front().index() == 0)
    {
        _logger->info("queuing replacement for local chain with with blocks {}-{}",
            tempchain.front().index(), tempchain.back().index());

        _tempchain = std::make_unique<ash::Blockchain>();
        *_tempchain = std::move(tempchain);
    }
    else if (tempchain.front().index() > _blockchain->back().index() + 1)
    {
        // we have a gap, so request the blocks in between
        auto startIdx = _blockchain->back().index() + 1;
        auto stopIdx = tempchain.back().index();

        _logger->info("temp chain has gap, requesting remote blocks {}-{}", startIdx, stopIdx);

        const auto msg = fmt::format(R"({{ "message":"chain","id1":{},"id2":{} }})",startIdx, stopIdx);
        connection->send(msg);
    }
    else
    {
        // at this point the first block of the temp chain exists within our
        // local chain or is just ONE ahead, but we don't know if that first 
        // block is valid, and if it is not then we will have to walk backwards 
        // by requesting one more block from the remote chain

        auto tempStartIdx = tempchain.front().index() - 1;
        assert(tempStartIdx < _blockchain->size() && tempStartIdx > 0);

        if (tempchain.front().previousHash() == _blockchain->at(tempStartIdx).hash())
        {
            _logger->info("caching update for local chain with remote blocks {}-{}",
                tempchain.front().index(), tempchain.back().index());

            _tempchain = std::make_unique<ash::Blockchain>();
            *_tempchain = tempchain;
        }
        else
        {
            auto startIdx = tempchain.front().index() - 1;
            auto stopIdx = tempchain.back().index();
            
            _logger->info("temp chain is misaligned, requesting remote blocks {}-{}", startIdx, stopIdx);

            const auto msg = fmt::format(R"({{ "message":"chain","id1":{},"id2":{} }})",startIdx, stopIdx);
            connection->send(msg);
        }
    }
}

} // namespace
