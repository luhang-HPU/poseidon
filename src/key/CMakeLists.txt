
# Source files in this directory
file(GLOB POSEIDON_KEY_SOURCE_FILES "*.cpp" "*.c")
set(POSEIDON_SOURCE_FILES  ${POSEIDON_SOURCE_FILES} 
        ${POSEIDON_KEY_SOURCE_FILES}
)

# Add header files for installation
file(GLOB POSEIDON_KEY_HRADER_FILES "*.h")
install (
    FILES
        ${POSEIDON_KEY_HRADER_FILES}
    DESTINATION
        ${POSEIDON_INCLUDES_INSTALL_DIR}/poseidon/src/key
)

set(POSEIDON_SOURCE_FILES ${POSEIDON_SOURCE_FILES} PARENT_SCOPE)
