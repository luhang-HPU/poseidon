file(GLOB POSEIDON_ALL_SOURCE_FILES "*.cpp" "*.c")
set(POSEIDON_SOURCE_FILES ${POSEIDON_ALL_SOURCE_FILES}
)

file(GLOB POSEIDON_ALL_HRADER_FILES "*.h")
install (FILES ${POSEIDON_ALL_HRADER_FILES}
    DESTINATION
        ${POSEIDON_INCLUDES_INSTALL_DIR}/poseidon/
)

add_subdirectory(advance)
add_subdirectory(evaluator)
add_subdirectory(factory)
add_subdirectory(key)
add_subdirectory(basics)
add_subdirectory(util)

set(POSEIDON_SOURCE_FILES ${POSEIDON_SOURCE_FILES} PARENT_SCOPE)
