#pragma once

#include <iostream>
#include <sstream>
#include <utility>
#include <vector>
#include <unordered_map>
#include <map>
#include <utility>
#include <string>
#include <stdexcept>
#include <typeinfo>
#include <algorithm>
#include <iomanip>
#include <functional>
#include <exception>

#include <cstring>
#include <cstdlib>
#include <ctime>

#include <windows.h>
#include <tchar.h>
#include <Dbghelp.h>
#include <shlwapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <atlstr.h>


#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")

namespace ost {
    // ancho de datos
    constexpr int NUM_WIDTH = 7;
    // for conversión de bytes
    constexpr int DIV = 1024;
    // program loop
    constexpr int MIN_TIME = 1;
    constexpr int MAX_TIME = 65535;
    // Límite de longitud de ID de proceso
    constexpr int PID_SIZE = 8;
    // Límite de longitud del nombre del proceso
    constexpr int PNAME_SIZE = 40;
    // Límite de longitud del conjunto de trabajo del proceso
    constexpr int PWORKSET_SIZE = 10;
    // Los límites superior e inferior de la identificación del proceso
    constexpr unsigned int PID_MIN = 0x4;
    constexpr unsigned int PID_MAX = 0xFFFFFFFC;
    // StrFormatByteSizeEx indicador de función
    constexpr unsigned int FLAG_FBS = 1;
    // unidad por defecto, 1，2，3，4KB,MB,GB,TB
    constexpr unsigned int DEFAULT_BTYPE = 1;
    // Límite de longitud de dirección
    constexpr unsigned int ADD_LEN = 16;
    // límite de longitud de cadena larga
    constexpr unsigned int LONG_STR_LEN = 16;
    // Límite de longitud de cadena corta
    constexpr unsigned int SHORT_STR_LEN = 10;
    // nombre de empresa
    constexpr char BTYPE_NAME[4] = {' ', 'K', 'M', 'G'};

    // Estructuras de enlace de argumentos y funciones
    struct ArguFunc {
        char shortName;
        std::string desc;
        std::function<void()> func;

        ArguFunc(char shortName, std::string desc, std::function<void()> func) : shortName(shortName),
                                                                                 desc(std::move(desc)),
                                                                                 func(std::move(func)) {};
    };
    // para establecer bytes
    extern std::pair<char, unsigned long> divByte;

    // Convertir byte a la unidad apropiada
    inline void btoStrDL(DWORDLONG src, PWSTR dst) {
        StrFormatByteSizeEx(src, FLAG_FBS, dst, MAX_PATH);
    }

    // error de salida
    inline void printError(const std::string &msg) {
        DWORD eNum;
        TCHAR sysMsg[256];

        eNum = GetLastError();
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      nullptr, eNum,
                      0, sysMsg, 256, nullptr);

        printf("[ERROR]: %s failed with error no: 0x%lx.\n%s\n", msg.c_str(), eNum, sysMsg);
    }

    void showTotal();

    void showSys();

    void showPerformance();

    void showEachProcess();

    void showHardwareInfo();

    void processInfo(DWORD pid);


}