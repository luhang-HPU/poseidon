# Source files in this directory
file(GLOB POSEIDON_SEAL_SOURCE_FILES "*.cpp" "*.c")
set(POSEIDON_SOURCE_FILES  ${POSEIDON_SOURCE_FILES} 
        ${POSEIDON_SEAL_SOURCE_FILES}
)

# Add header files for installation
file(GLOB POSEIDON_SEAL_HRADER_FILES "*.h")
install (
    FILES
        ${POSEIDON_SEAL_HRADER_FILES}
    DESTINATION
        ${POSEIDON_INCLUDES_INSTALL_DIR}/poseidon/basics
)

add_subdirectory(util)
set(POSEIDON_SOURCE_FILES ${POSEIDON_SOURCE_FILES} PARENT_SCOPE)
