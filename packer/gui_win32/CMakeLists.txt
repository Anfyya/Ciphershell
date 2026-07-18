# CipherShell GUI (Win32) CMakeLists.txt
#
# 独立的原生 Win32 GUI 可执行文件：ciphershell_gui.exe。
#
# 故意不链接 ciphershell_packer 静态库——GUI 进程和打包核心逻辑完全解耦，
# 两者只通过 CreateProcess 调用现有的 ciphershell.exe 交互（把界面上填写的
# 参数一部分转成命令行参数，一部分写成临时 TOML 配置文件用 -c 传入，
# 见 process_runner.*/cli_builder.*/toml_writer.*）。
#
# 这里用到的 IFileOpenDialog/IFileSaveDialog/IDropTarget/ComCtl32 都是真实
# Win32 API，compat/windows_compat.h 那套给打包核心用的 Linux 兼容层并不
# 覆盖这些，所以只由调用方在 WIN32 时才 add_subdirectory 这个目录。

add_executable(ciphershell_gui WIN32
    main.cpp
    main_window.cpp
    ui_helpers.cpp
    control_ids.cpp
    toml_writer.cpp
    cli_builder.cpp
    process_runner.cpp
    file_dialogs.cpp
    drop_target.cpp
    text_convert.cpp
    win32_error.cpp
    resources.rc
)

target_include_directories(ciphershell_gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(ciphershell_gui PRIVATE UNICODE _UNICODE)

target_link_libraries(ciphershell_gui PRIVATE
    comctl32
    ole32
    uuid
    shell32
    gdi32
    user32
    advapi32
)

if(MSVC)
    target_compile_options(ciphershell_gui PRIVATE /sdl /permissive-)
    # 清单已经通过 resources.rc（CREATEPROCESS_MANIFEST_RESOURCE_ID）显式
    # 嵌入，关掉链接器自动生成/合并清单，避免和这份重复冲突。
    set_target_properties(ciphershell_gui PROPERTIES LINK_FLAGS "/MANIFEST:NO")
endif()
