#include "Gui.hpp"
#include "OpenXcTransport.hpp"
#include "UDSClient.hpp"

#include <QApplication>

#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc >= 2 && std::strcmp(argv[1], "--test-vf8-gateway") == 0) {
        const std::string device = argc >= 3 ? argv[2] : "usb";
        openxc::Transport transport;
        std::string error;
        if (!transport.connect(device, error)) {
            std::fprintf(stderr, "Unable to connect to OpenXC VI: %s\n", error.c_str());
            return 1;
        }

        UDSClient uds(transport, obd::kPhysicalEcuLogical);
        if (!uds.diagnosticSessionControl(obd::kPhysicalRequestId,
                                          UdsSession::Default, error)) {
            std::fprintf(stderr, "VF8 gateway session check failed: %s\n", error.c_str());
            return 1;
        }
        auto vin = uds.readDataByIdentifier(obd::kPhysicalRequestId, 0xF190, error);
        if (!vin) {
            std::fprintf(stderr, "VF8 gateway VIN check failed: %s\n", error.c_str());
            return 1;
        }
        std::printf("VF8 gateway online; VIN: %.*s\n",
                    static_cast<int>(vin->size()),
                    reinterpret_cast<const char*>(vin->data()));
        return 0;
    }

    if (argc >= 2 && std::strcmp(argv[1], "--check-openxc") == 0) {
        const std::string device = argc >= 3 ? argv[2] : "usb";
        openxc::Transport transport;
        std::string error;
        if (!transport.connect(device, error)) {
            std::fprintf(stderr, "Unable to connect to OpenXC VI: %s\n", error.c_str());
            return 1;
        }
        std::printf("OpenXC VI connected: %s\n", transport.connectedPath().c_str());
        return 0;
    }

    if (argc >= 2 && std::strcmp(argv[1], "--enter-bootloader") == 0) {
        const std::string device = argc >= 3 ? argv[2] : "usb";
        openxc::Transport transport;
        std::string error;
        if (!transport.connect(device, error)) {
            std::fprintf(stderr, "Unable to connect to OpenXC VI: %s\n", error.c_str());
            return 1;
        }
        if (!transport.requestBootloader(error)) {
            std::fprintf(stderr, "Unable to request bootloader: %s\n", error.c_str());
            return 1;
        }
        std::printf("Bootloader request sent; waiting for the LPC1759 USB volume.\n");
        return 0;
    }

    QApplication app(argc, argv);

    QApplication::setApplicationName("VinFast Diagnostic Scanner");
    QApplication::setOrganizationName("VinFast Owners Association");

    Gui w;
    w.show();
    return app.exec();
}
