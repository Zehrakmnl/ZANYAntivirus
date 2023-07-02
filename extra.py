from secenekeler import Ui_MainWindow0
from PyQt5 import QtWidgets
class call():
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow0()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())