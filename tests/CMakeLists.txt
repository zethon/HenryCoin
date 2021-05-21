project(tests)

function(create_test testname FILES)

    add_executable(test_${testname}
        main.cpp
        test_${testname}.cpp
        ${FILES}
    )

    target_link_libraries(test_${testname}
        PUBLIC
            ${CONAN_LIBS}
    )

    add_test(NAME test_${testname}
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/test_${testname}
    )

endfunction(create_test)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

set(ASH_FILES
    ../src/AshLogger.cpp
    ../src/AshLogger.h
    ../src/Block.cpp
    ../src/Block.h
    ../src/Blockchain.cpp
    ../src/Blockchain.h
    # ../src/Miner.cpp
    ../src/Miner.h
    ../src/Transactions.cpp
    ../src/Transactions.h

    ../src/CryptoUtils.cpp
    ../src/CryptoUtils.h
)

create_test("blockchain" "${ASH_FILES}")
create_test("crypto" "${ASH_FILES}")
create_test("merkleroot" "${ASH_FILES}")
