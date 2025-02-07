# Add header files for installation
file(GLOB POSEIDON_HARDWARE_INCLUDE_HRADER_FILES "*.h")
install (
    FILES
        ${POSEIDON_HARDWARE_INCLUDE_HRADER_FILES}
    DESTINATION
        ${POSEIDON_INCLUDES_INSTALL_DIR}/poseidon/src/hardware_include
)
