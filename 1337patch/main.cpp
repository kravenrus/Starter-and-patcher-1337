#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "command_line.h"
#include "utils.h"
#include "patching.h"

int run_process(const std::string& path)
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	if (!CreateProcess(nullptr, const_cast<char*>(path.c_str()), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) { return -1; }

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return pi.dwProcessId;
}

int main(int argc, char* argv[])
{
	try
	{
		command_line command_line;


		if (!command_line.parse(argc, argv))
		{
			print_usage();
			return 0;
		}

		std::vector<patch_info> patch_infos = read_1337_file(command_line.patch_file);

		DWORD pid;

		if (command_line.process_name.empty())
			pid = command_line.process_id;
		else
		{
			pid = find_process_by_name(command_line.process_name);
		}

		if (!command_line.executable_path.empty()) {
			std::ifstream file(command_line.executable_path);
			if (!file)
			{
				std::cerr << "Unable to open executable file \"" << command_line.executable_path << "\"." << std::endl;
				return 2;
			}

			pid = run_process(command_line.executable_path);

			std::cout << "Started PID \"" << pid << "\"." << std::endl;

			Sleep(1000);
		}

		if (pid == -1)
		{
			std::cout << "Cannot find process with name \"" << command_line.process_name << "\"." << std::endl;
			return 3;
		}

		winapi_handle process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, pid);

		if (process == nullptr)
			throw winapi_exception("OpenProcess", GetLastError());

		std::vector<module_info> module_infos = get_module_infos(process);

		if (!command_line.force)
		{
			if (!verify_patches(process, module_infos, patch_infos, command_line.revert))
			{
				if (verify_patches(process, module_infos, patch_infos, !command_line.revert))
				{
					if (!command_line.revert)
						std::cout << "Patches have already been applied." << std::endl;
					else
						std::cout << "Patches have not been applied." << std::endl;
					return 1;
				}
				else
				{
					std::cerr << "Encountered unexpected data at patch locations. Specify option -force to apply/revert patches anyway." << std::endl;
					return 2;
				}
			}
		}

		apply_patches(process, module_infos, patch_infos, command_line.revert);

		if (!command_line.revert)
			std::cout << "Patches applied successfully." << std::endl;
		else
			std::cout << "Patches reverted successfully." << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 4;
	}

	return 0;
}