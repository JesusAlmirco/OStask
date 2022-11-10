#include "cmdline.h"

namespace ost {
    // Menú del programa
    const std::map<std::string, ost::ArguFunc> funcMap = {
            {"perf",
                    ArguFunc('p', "show system performance value info.", &ost::showPerformance)},
            {"sys",
                    ArguFunc('s', "show system memory info.", &ost::showSys)},
            {"total",
                    ArguFunc('t', "show total memory usage.", &ost::showTotal)},
            {"each",
                    ArguFunc('e', "show each process info.", &ost::showEachProcess)},
            {"hardware",
                    ArguFunc('w', "show PC hardware information.", &ost::showHardwareInfo)}
    };
    // Unidad de visualización del programa(B,KB,MB,GB)
    std::pair<char, unsigned long> divByte;
}

int main(int argc, char **argv) {
    // La unidad por defecto, si el elemento anterior es 0, es automático
    ost::divByte = std::make_pair(0, 1);
    // Manejo de parámetros de línea de comando
    cmdline::parser par;

    std::ios::sync_with_stdio();

    par.set_program_name("OStask");
    // añadir tipo de parámetro
    par.add<unsigned long>("inquire", 'i', "Inquire the selected process info.",
                           false, ost::PID_MIN, cmdline::range<unsigned long>(ost::PID_MIN, ost::PID_MAX));
    par.add<unsigned int>("loop", 'l', "loop this program from [1-65535] second.",
                          false, ost::MIN_TIME, cmdline::range(ost::MIN_TIME, ost::MAX_TIME));
    par.add<int>("type", 'y', "Set the show byte type[0=B,1=KB,2=MB,3=GB],Auto decide if not use this.",
                 false, ost::DEFAULT_BTYPE, cmdline::range(0, 3));

    par.add("help", '?', "show help message.");
    par.add("copyright", 'c', "show copyright and license information.");
    par.add("all", 'a', "show all info.");

    for (auto &&[arg, arf]: ost::funcMap) {
        par.add(arg, arf.shortName, arf.desc);
    }
    // Si hay ayuda o ningún parámetro, muestra la información de ayuda
    if (argc <= 1 || !par.parse(argc, argv) || par.exist("help")) {
        std::cout << par.error() << par.usage();
        return 0;
    }
    // Mostrar licencias de código abierto
    if (par.exist("copyright")) {
        std::cout << "[LICENSE]:\n"
                     "\n"
                     "Copyright 2022 JesusAlmirco\n"
                     "\n"
                     "Licensed under the Apache License, Version 2.0 (the \"License\");\n"
                     "you may not use this file except in compliance with the License.\n"
                     "You may obtain a copy of the License at\n"
                     "\n"
                     "http://www.apache.org/licenses/LICENSE-2.0\n"
                     "\n"
                     "Unless required by applicable law or agreed to in writing, software\n"
                     "distributed under the License is distributed on an \"AS IS\" BASIS,\n"
                     "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
                     "See the License for the specific language governing permissions and\n"
                     "limitations under the License.\n"
                     "\n";
        return 0;
    }
    // Establecer las unidades utilizadas por el programa
    if (par.exist("type")) {
        int type = par.get<int>("type");
        ost::divByte.first = ost::BTYPE_NAME[type];
        for (int i = 0; i < type; ++i)
            ost::divByte.second *= ost::DIV;
    }

    // Tabla de funciones de llamada según parámetros
    auto doFunc = [&]() {
        for (auto &&[arg, arf]: ost::funcMap)
            if (par.exist("all") || par.exist(arg))
                arf.func();
    };

    // Consultar un solo proceso
    if (par.exist("inquire")) {
        auto pid = par.get<unsigned long>("inquire");
        ost::processInfo(pid);
        return 0;
    }
    // ejecución de loop
    if (par.exist("loop")) {
        auto loopCount = par.get<unsigned int>("loop");
        while (loopCount--) {
            system("cls");
            doFunc();
            printf("[LEFT TIME]:%d", loopCount);
            Sleep(1000);
        }
    } else
        // Ejecutar por defecto
        doFunc();
    return 0;
}