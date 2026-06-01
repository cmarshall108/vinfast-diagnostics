#include "Gui.hpp"

#include <QApplication>

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    QApplication::setApplicationName("VinFast Diagnostic Scanner");
    QApplication::setOrganizationName("VinFast Owners Association");

    Gui w;
    w.show();
    return app.exec();
}
