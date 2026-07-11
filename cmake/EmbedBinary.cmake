if(NOT DEFINED INPUT_FILE OR NOT DEFINED OUTPUT_FILE OR NOT DEFINED SYMBOL_NAME)
    message(FATAL_ERROR "EmbedBinary.cmake requires INPUT_FILE, OUTPUT_FILE and SYMBOL_NAME")
endif()

file(READ "${INPUT_FILE}" binary_hex HEX)
string(LENGTH "${binary_hex}" hex_length)
math(EXPR byte_count "${hex_length} / 2")

file(WRITE "${OUTPUT_FILE}"
    "#pragma once\n#include <cstddef>\n#include <cstdint>\n\n"
    "static const std::uint8_t ${SYMBOL_NAME}[] = {\n")

set(line "    ")
if(byte_count GREATER 0)
    math(EXPR last_index "${byte_count} - 1")
    foreach(index RANGE 0 ${last_index})
        math(EXPR hex_offset "${index} * 2")
        string(SUBSTRING "${binary_hex}" ${hex_offset} 2 value)
        string(APPEND line "0x${value},")
        math(EXPR column "(${index} + 1) % 16")
        if(column EQUAL 0)
            file(APPEND "${OUTPUT_FILE}" "${line}\n")
            set(line "    ")
        endif()
    endforeach()
endif()
if(NOT line STREQUAL "    ")
    file(APPEND "${OUTPUT_FILE}" "${line}\n")
endif()
file(APPEND "${OUTPUT_FILE}"
    "};\nstatic constexpr std::size_t ${SYMBOL_NAME}Size = sizeof(${SYMBOL_NAME});\n")
