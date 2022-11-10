#include "OStask.h"

namespace ost {
    // Tabla de arquitectura del sistema
    const std::unordered_map<WORD, std::string> archList = {{9,      "x64"},
                                                            {5,      "ARM"},
                                                            {12,     "ARM64"},
                                                            {6,      "Intel Itanium"},
                                                            {0,      "x86"},
                                                            {0xffff, "Unknown"}};
    // Tabla de estado de bloques de memoria
    const std::unordered_map<DWORD, std::string> mbiStateMap = {{MEM_COMMIT,  "Committed"},
                                                                {MEM_FREE,    "Free"},
                                                                {MEM_RESERVE, "Reserved"}};
    // tabla de protección de bloque de memoria
    const std::unordered_map<DWORD, std::string> mbiProtectMap = {{PAGE_EXECUTE,           "Exec"},
                                                                  {PAGE_EXECUTE_READ,      "Read/Exec"},
                                                                  {PAGE_EXECUTE_READWRITE, "Read/Write/Exec"},
                                                                  {PAGE_EXECUTE_WRITECOPY, "Read/Copy/Exec"},
                                                                  {PAGE_NOACCESS,          "No Access"},
                                                                  {PAGE_READONLY,          "Read"},
                                                                  {PAGE_READWRITE,         "Read/Write"},
                                                                  {PAGE_WRITECOPY,         "Read/Copy"},
                                                                  {PAGE_TARGETS_INVALID,   "Invalid"},
                                                                  {PAGE_GUARD,             "Guard"},
                                                                  {PAGE_NOCACHE,           "No Cache"},
                                                                  {PAGE_WRITECOMBINE,      "Write Combine"},};
    // Tabla de tipos de bloques de memoria
    const std::unordered_map<DWORD, std::string> mbiTypeMap = {{MEM_IMAGE,   "Image"},
                                                               {MEM_MAPPED,  "Mapped"},
                                                               {MEM_PRIVATE, "Private"}};
}

// Mostrar información de memoria global
void ost::showTotal() {
    printf("[TOTAL]:\n");
    MEMORYSTATUSEX lpBuffer;
    lpBuffer.dwLength = sizeof(MEMORYSTATUSEX);

    // Obtener información de la memoria del sistema
    if (GlobalMemoryStatusEx(&lpBuffer) == 0) {
        ost::printError("Get Memory Status");
    }
    // Mostrar porcentaje de uso de memoria
    printf("Percent of memory in use: %ld%%.\n", lpBuffer.dwMemoryLoad);
    printf("\nPhysical memory usage:\n    Available / Total: ");

    if (ost::divByte.first) {
        // Mostrar usando las unidades ingresadas
        printf("%*I64d / %*I64d %cB.\n",
               ost::NUM_WIDTH, lpBuffer.ullAvailPhys / ost::divByte.second,
               ost::NUM_WIDTH, lpBuffer.ullTotalPhys / ost::divByte.second, ost::divByte.first);
    } else {
        // Mostrar usando unidades predeterminadas
        WCHAR szAvaSize[MAX_PATH];
        WCHAR szTotSize[MAX_PATH];
        ost::btoStrDL(lpBuffer.ullAvailPhys, szAvaSize);
        ost::btoStrDL(lpBuffer.ullTotalPhys, szTotSize);
        printf("%*ls / %*ls.\n", ost::NUM_WIDTH, szAvaSize, ost::NUM_WIDTH, szTotSize);
    }
    putchar('\n');
}

// mostrar información del sistema
void ost::showSys() {
    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(SYSTEM_INFO));

    GetSystemInfo(&si);

    // Obtener la arquitectura del sistema
    auto &&sysType = ost::archList.count(si.wProcessorArchitecture) ?
                     ost::archList.at(si.wProcessorArchitecture) : "Unable";

    printf("[SYSTEM]:\n");
    printf("Process architecture: %s.\n", sysType.c_str());


    // Número de procesadores lógicos
    printf("Number of logical processors: %ld.\n", si.dwNumberOfProcessors);

    // tamaño de página
    WCHAR szPageSize[MAX_PATH];
    ost::btoStrDL(si.dwPageSize, szPageSize);
    printf("Page size: %ls.\n", szPageSize);

    // tamaño de la memoria física
    ULONGLONG ramSize;
    GetPhysicallyInstalledSystemMemory(&ramSize);
    ramSize *= 1024;
    WCHAR szRamSize[MAX_PATH];
    ost::btoStrDL(ramSize, szRamSize);
    printf("Physical Memory(RAM): %ls.\n", szRamSize);

    // Rango de direcciones de memoria accesible
    printf("Accessible memory address range: 0x%p - 0x%p.\n",
           si.lpMinimumApplicationAddress,
           si.lpMaximumApplicationAddress);
    putchar('\n');
}

// Mostrar información de rendimiento
void ost::showPerformance() {
    PERFORMANCE_INFORMATION pi;
    pi.cb = sizeof(PERFORMANCE_INFORMATION);
    GetPerformanceInfo(&pi, pi.cb);

    // tamaño de página
    printf("[PERFORMANCE]:\nPage size: ");
    WCHAR szPageSize[MAX_PATH];
    ost::btoStrDL(pi.PageSize, szPageSize);
    printf("%ls.\n", szPageSize);

    // Enviado/Páginas generales
    printf("Currently committed pages amount:\n");
    printf("\tCurrent / Max: %llu / %llu.\n", pi.CommitTotal, pi.CommitLimit);

    // Número máximo de páginas históricas
    printf("Max committed pages amount in history: %llu\n\n", pi.CommitPeak);

    // Páginas físicas disponibles/totales
    printf("Currently physical pages amount:\n");
    printf("\tAvailable / Max: %llu / %llu.\n", pi.PhysicalAvailable, pi.PhysicalTotal);

    // Número de páginas almacenadas en caché por el sistema
    printf("System cache pages amount: %llu.\n\n", pi.SystemCache);

    // Paginadas/Sin paginar/Total de páginas de memoria
    printf("Currently kernel pools:\n");
    printf("\tPaged/Nonpaged: %llu / %llu.\n    All: %llu.\n\n",
           pi.KernelPaged, pi.KernelNonpaged, pi.KernelTotal);

    printf("Currently program amount:\n");
    // número actual de manijas
    printf("\tOpened handles: %lu\n", pi.HandleCount);
    // Número actual de procesos
    printf("\tProcesses: %lu\n", pi.ProcessCount);
    // Número actual de hilos
    printf("\tThreads: %lu\n", pi.ThreadCount);

    putchar('\n');
}

// mostrar toda la información del proceso
void ost::showEachProcess() {

    using namespace std;
    // obtener una instantánea de todos los procesos
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 pointOfSnap;
    pointOfSnap.dwSize = sizeof(PROCESSENTRY32);
    printf("[PROCESS LIST]:\n");

    // Muestra el ID, el nombre, el tamaño del conjunto de trabajo, el tamaño del grupo paginado de cada proceso
    printf("%-*s", ost::PID_SIZE, "ID");
    printf("\t%-*s", ost::PNAME_SIZE, "Name");
    printf("\t%-*s", ost::PWORKSET_SIZE, "WorkSet");
    printf("\t%-*s", ost::PWORKSET_SIZE, "PagePool");
    putchar('\n');

    // Obtenga la primera instantánea del proceso
    BOOL snapExist = Process32First(hSnapShot, &pointOfSnap);
    while (snapExist) {
        // Recorra todas las instantáneas del proceso
        HANDLE pHandle = OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE,
                pointOfSnap.th32ProcessID);

        PROCESS_MEMORY_COUNTERS pMemCount;
        ZeroMemory(&pMemCount, sizeof(PROCESS_MEMORY_COUNTERS));

        if (GetProcessMemoryInfo(pHandle, &pMemCount, sizeof(PROCESS_MEMORY_COUNTERS)) == TRUE) {
            // ID
            printf("%-*lu", ost::PID_SIZE, pointOfSnap.th32ProcessID);
            // nombre del proceso
            printf("\t%-*s", ost::PNAME_SIZE, pointOfSnap.szExeFile);
            // Conjunto de trabajo y tamaño de grupo paginado
            if (ost::divByte.first) {
                printf("\t%-*llu%cB", ost::PWORKSET_SIZE, pMemCount.WorkingSetSize / ost::divByte.second,
                       ost::divByte.first);
                printf("\t%-*llu%cB", ost::PWORKSET_SIZE, pMemCount.QuotaPagedPoolUsage / ost::divByte.second,
                       ost::divByte.first);
            } else {
                WCHAR szWorkSize[MAX_PATH];
                WCHAR szQuoSize[MAX_PATH];
                ost::btoStrDL(pMemCount.WorkingSetSize, szWorkSize);
                ost::btoStrDL(pMemCount.QuotaPagedPoolUsage, szQuoSize);
                printf("\t%-*ls", ost::PWORKSET_SIZE, szWorkSize);
                printf("\t%-*ls", ost::PWORKSET_SIZE, szQuoSize);
            }
            putchar('\n');
        }
        // Obtener la siguiente instantánea del proceso
        snapExist = Process32Next(hSnapShot, &pointOfSnap);
    }

}

// Mostrar información de hardware
void ost::showHardwareInfo() {
    printf("[HARDWARE INFO]:\n");

    // CPU
    printf("[CPU]:\n");
    // Leer información de la CPU
    int cpuInfo[4] = {-1};
    unsigned nExIds, i;
    char CPUBrandString[0x40];

    memset(CPUBrandString, 0, sizeof(CPUBrandString));
    __cpuid(cpuInfo, 0);
    memcpy(CPUBrandString, cpuInfo + 1, sizeof(int));
    memcpy(CPUBrandString + 4, cpuInfo + 3, sizeof(int));
    memcpy(CPUBrandString + 8, cpuInfo + 2, sizeof(int));
    // proveedor de CPU
    printf("\tCPU Vendor: %s.\n", CPUBrandString);

    __cpuid(cpuInfo, 0x80000000);
    nExIds = cpuInfo[0];
    for (i = 0x80000000; i <= nExIds; ++i) {
        __cpuid(cpuInfo, i);
        // Interpret CPU brand string
        if (i == 0x80000002)
            memcpy(CPUBrandString, cpuInfo, sizeof(cpuInfo));
        else if (i == 0x80000003)
            memcpy(CPUBrandString + 16, cpuInfo, sizeof(cpuInfo));
        else if (i == 0x80000004)
            memcpy(CPUBrandString + 32, cpuInfo, sizeof(cpuInfo));
    }
    // nombre del tipo de CPU
    printf("\tCPU Type: %s.\n", CPUBrandString);

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // CPU Arquitectura
    auto &&sysType = ost::archList.count(sysInfo.wProcessorArchitecture) ?
                     ost::archList.at(sysInfo.wProcessorArchitecture) : "Unable";

    printf("\tProcess architecture: %s.\n", sysType.c_str());
    // CPU Número de procesadores lógicos
    printf("\tNumber of logical processors: %ld.\n\n", sysInfo.dwNumberOfProcessors);


    // GPU
    printf("[GPU]:\n");
    for (int j = 0;; j++) {
        // PantallaCiclo GPU información
        DISPLAY_DEVICE dd = {sizeof(dd), 0};
        BOOL f = EnumDisplayDevices(nullptr, j, &dd, EDD_GET_DEVICE_INTERFACE_NAME);
        if (!f)
            break;
        // GPU Nombre
        printf("\t%s\n", dd.DeviceName);
        // GPU Escribe
        printf("\t%s\n", dd.DeviceString);
    }
    putchar('\n');
}

// Mostrar información de proceso individual
void ost::processInfo(DWORD pid) {
    printf("[PROCESS INFO]: id: %lu\n", pid);

    // Instanciar del proceso abierto
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hp == nullptr) {
        ost::printError("Open process");
        return;
    }
    DWORD len = MAX_PATH;

    // Obtener nombre de ruta del proceso
    CHAR szProName[MAX_PATH];
    QueryFullProcessImageName(hp,0,szProName,&len);
    printf("[PATH]: %s\n", szProName);

    printf("[FORMAT]:Region Address(Length) | Status | Protect | Type | Model\n");
    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(SYSTEM_INFO));
    GetSystemInfo(&si);
    // Procesar espacio de memoria virtual
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));

    // dirección de memoria inicial
    auto accAdd = si.lpMinimumApplicationAddress;

    // dirección de memoria final
    auto maxAdd = si.lpMaximumApplicationAddress;
    while (accAdd < maxAdd) {
        if (VirtualQueryEx(hp, accAdd,
                           &mbi,
                           sizeof(MEMORY_BASIC_INFORMATION)) == 0) {
            ost::printError("Get Virtual Memory");
            break;
        }
        LPVOID endAdd = reinterpret_cast<PBYTE>(accAdd) + mbi.RegionSize;
        // Mostrar la dirección inicial y final y la longitud del bloque
        printf("%0*llX - %0*llX", ost::ADD_LEN, reinterpret_cast<ULONG_PTR>(accAdd),
               ost::ADD_LEN, reinterpret_cast<ULONG_PTR>(endAdd));
        if (ost::divByte.first) {
            printf("(%llu%cB)\t", mbi.RegionSize / ost::divByte.second, ost::divByte.first);
        } else {
            WCHAR szRegSize[MAX_PATH] = {0};
            ost::btoStrDL(mbi.RegionSize, szRegSize);
            printf("(%ls)\t", szRegSize);
        }
        // mostrar el estado del bloque
        printf("%-*s\t", ost::SHORT_STR_LEN,
               ost::mbiStateMap.count(mbi.State) ?
               ost::mbiStateMap.at(mbi.State).c_str() :
               "Unknown");
        if (mbi.Protect == 0 && mbi.State != MEM_FREE) {
            mbi.Protect = PAGE_READONLY;
        }
        // Mostrar tipo de protección de bloque
        printf("%-*s ", ost::LONG_STR_LEN,
               ost::mbiProtectMap.count(mbi.Protect) ?
               ost::mbiProtectMap.at(mbi.Protect).c_str() :
               "Unknown");
        // Mostrar tipo de bloque
        printf("%-*s", ost::SHORT_STR_LEN,
               ost::mbiTypeMap.count(mbi.Type) ?
               ost::mbiTypeMap.at(mbi.Type).c_str() :
               "Unknown");
        TCHAR szFilename[MAX_PATH];
        // El proceso actual ha cargado el módulo.
        if (GetModuleFileName(
                reinterpret_cast<HMODULE>(accAdd),
                szFilename,
                MAX_PATH) > 0) {
            // eliminar la ruta del prefijo
            PathStripPath(szFilename);
            printf("\tModule: %s", szFilename);
        }
        putchar('\n');
        accAdd = endAdd;

    }
}