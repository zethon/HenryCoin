#pragma once

#include <cstdint>
#include <vector>

#include "Settings.h"
#include "Block.h"

namespace ash
{

#ifdef _RELEASE
constexpr auto TARGET_TIMESPAN = 10u * 60u; // in seconds
constexpr auto TARGET_SPACING = 25u; // in blocks
#else
constexpr auto TARGET_TIMESPAN  = 60u; // in seconds
constexpr auto BLOCK_INTERVAL   = 10u; // in blocks
#endif

class Blockchain;
using BlockChainPtr = std::unique_ptr<Blockchain>;

void to_json(nl::json& j, const Blockchain& b);
void from_json(const nl::json& j, Blockchain& b);

template<typename NumberT>
class CumulativeMovingAverage
{
    NumberT     _total = 0;
    std::size_t _count = 0;
public:
    float value() const
    {
        // TODO: pretty sure only one cast is need, but not 100% sure
        return (static_cast<float>(_total) / static_cast<float>(_count));
    }

    void addValue(NumberT v)
    {
        _total += v;
        _count++;
    }

    void reset()
    {
        _total = 0;
        _count = 0;
    }
};

class Blockchain 
{

friend class ChainDatabase;
    
    std::vector<Block>  _blocks;

    friend void to_json(nl::json& j, const Blockchain& b);
    friend void from_json(const nl::json& j, Blockchain& b);

public:
    Blockchain() = default;

    auto begin() const -> decltype(_blocks.begin())
    {
        return _blocks.begin();
    }

    auto end() const -> decltype(_blocks.end())
    {
        return _blocks.end();
    }

    auto front() const -> decltype(_blocks.front())
    {
        return _blocks.front();
    }

    auto back() const -> decltype(_blocks.back())
    {
        return _blocks.back();
    }

    std::size_t size() const 
    { 
        return _blocks.size(); 
    }

    void clear()
    {
        _blocks.clear();
    }

    void resize(std::size_t size)
    {
        _blocks.resize(size);
    }

    auto at(std::size_t index) -> decltype(_blocks.at(index))
    {
        return _blocks.at(index);
    }

    bool addNewBlock(const Block& block);
    bool addNewBlock(const Block& block, bool checkPreviousBlock);

    const Block& getBlockByIndex(std::size_t idx) 
    { 
        return _blocks.at(idx); 
    }

    bool isValidBlockPair(std::size_t idx) const;
    bool isValidChain() const;

    std::uint64_t cumDifficulty() const
    {
        return cumDifficulty(_blocks.size() - 1);
    }

    std::uint64_t cumDifficulty(std::size_t idx) const;

    std::uint64_t getAdjustedDifficulty()
    {
        const auto chainsize = size();
        assert(chainsize > 0);

        if (((back().index() + 1) % BLOCK_INTERVAL) != 0)
        {
            return back().difficulty();
        }

        const auto& firstBlock = at(size() - BLOCK_INTERVAL);
        const auto& lastBlock = back();
        const auto timespan = 
            static_cast<std::uint64_t>(lastBlock.time() - firstBlock.time());

        std::cout << "first: " << firstBlock.time() << '\n';
        std::cout << "last : " << lastBlock.time() << '\n';

        if (timespan < (TARGET_TIMESPAN / 2))
        {
            return lastBlock.difficulty() + 1;
        }
        else if (timespan > (TARGET_TIMESPAN * 2))
        {
            return lastBlock.difficulty() - 1;
        }

        return lastBlock.difficulty();
    }
};

}
