#!/urs/bin/python3
#-*- coding: utf-8 -*-

from PyQt5 import QtWidgets
from PyQt5.uic import loadUi
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
import sys
from HillCipher import *

KEY_login = "encode123"

# Класс отвечающий за стартовое окно
class Login(QMainWindow):
    def __init__(self):
        super(Login, self).__init__()
        loadUi("qt_login.ui", self)
        self.login()

    def login(self):
        self.line_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login_btn.clicked.connect(lambda: self.personal_ac())
        self.registr_btn.clicked.connect(lambda: self.registr())

    def personal_ac(self):
        global username
        username = self.line_username.text().strip()
        password = self.line_password.text()
        if check_login(username, password, KEY_login):
            self.line_username.setText('')
            self.line_password.setText('')
            widget.addWidget(account_window)
            widget.setFixedWidth(850)
            widget.setFixedHeight(700)
            widget.setCurrentWidget(account_window)
        else:
            error = QMessageBox()
            error.setWindowTitle("Ошибка\t\t\t\t\t")
            error.setText("Введен неверный логин или пароль.")
            error.setIcon(QMessageBox.Warning)
            error.setStandardButtons(QMessageBox.Ok)
            error.exec_()
    def registr(self):
        self.line_username.setText('')
        self.line_password.setText('')
        widget.setCurrentWidget(new_ac_window)

# Класс отвечающий за окно регистрации
class Registration(QMainWindow):
    def __init__(self):
        super(Registration, self).__init__()
        loadUi("qt_registration.ui", self)
        self.registration()

    def registration(self):
        self.new_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.replay_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.creat_ac_btn.clicked.connect(lambda: self.login_window(True))
        self.back_btn.clicked.connect(lambda: self.login_window(False))

    def login_window(self, flag):
        if flag:
            username = self.new_username.text().strip()
            password = self.new_password.text()
            replay_password = self.replay_password.text()
            if password != replay_password:
                error = QMessageBox()
                error.setWindowTitle("Ошибка\t\t\t\t\t")
                error.setText("Пароли не совпадают!")
                error.setIcon(QMessageBox.Warning)
                error.setStandardButtons(QMessageBox.Ok)
                error.exec_()
                return False
            registr = check_registr(username, password, KEY_login)
            if registr ==True:
                flag = False
            else:
                error = QMessageBox()
                error.setWindowTitle("Ошибка\t\t\t\t\t")
                error.setText("Введены неверный данные!")
                error.setIcon(QMessageBox.Warning)
                error.setStandardButtons(QMessageBox.Ok)
                error.setDetailedText(" Требования к паролю:\n"
                                      "1) Пароль может состоять из: \n"
                                      "- Латинского алфавита (a-z; A-Z)\n"
                                      "- знаков препинания ('.', '!', '?', ',', '_')\n"
                                      "- цифр (0-9)\n"
                                      "2) Длина пароля должна быть не менее 8 и не более 30\n"
                                      "Требования к логину: \n"
                                      " Длина логина должна быть не менее 2 и не более 50\n\n"
                                      "Примечание: Если все требования выполняются, но программа выдает ошибку. Это значит,"
                                      " что пользователь с таким логином или паролем уже существует.")
                error.exec_()
        if not flag:
            self.new_username.setText('')
            self.new_password.setText('')
            self.replay_password.setText('')
            return widget.setCurrentWidget(login_window)

# Класс отвечающий за личный кабинет
class Personal_account(QMainWindow):
    def __init__(self):
        super(Personal_account, self).__init__()
        loadUi("qt_personal_ac.ui", self)
        self.encrypt_btn.clicked.connect(lambda: self.encrypt())
        self.dencrypt_btn.clicked.connect(lambda: self.dencrypt())
        self.exit_btn.clicked.connect(lambda: self.exit())

        self.encrypt_text.setAcceptRichText(False)
        self.dencrypt_text.setAcceptRichText(False)
        self.encrypt_text.setPlaceholderText("Введите текст, который надо зашифровать")
        self.key_1.setPlaceholderText("Введите ключ для шифрования")
        self.key_encode_file.setReadOnly(True)
        self.dencrypt_text.setReadOnly(True)
        self.key_file.setPlaceholderText("Введите ключ файла, который надо расшифровать")

    def exit(self):
        error = QMessageBox()
        error.setWindowTitle("Предупреждение\t\t\t\t\t")
        error.setText("Вы уверены что хотите выйти из лчного кабинета?")
        error.setStandardButtons(QMessageBox.Ok|QMessageBox.Cancel)
        error.buttonClicked.connect(self.click_btn)
        error.exec_()

    def click_btn(self, btn):
        if btn.text() == 'OK':
            self.encrypt_text.setText("")
            self.dencrypt_text.setText("")
            self.key_1.setText("")
            self.key_file.setText("")
            self.key_encode_file.setText("")
            widget.removeWidget(account_window)
            widget.setFixedWidth(560)
            widget.setFixedHeight(350)
            widget.setCurrentWidget(login_window)

    def encrypt(self):
        enc_text = self.encrypt_text.toPlainText()
        key = self.key_1.text()
        enc_text = convert_text_to_digits(enc_text, 'text')
        key_digit = key_verification(key, 'text')
        if key_digit != 0:
            if enc_text != 0:
                key_file = encode(enc_text, key_digit, 'text')
                if key_file == False:
                    self.error_key(False)
                else:
                    self.key_encode_file.setText(key_file)
            else:
                self.error_key(True)
        else:
            self.error_key(False)

    def error_key(self, flag):
        error = QMessageBox()
        error.setWindowTitle("Ошибка\t\t\t\t\t")
        if not flag:
            error.setText("Введен неверный ключ.")
        else:
            error.setText("Введен неверный текст.")
        error.setIcon(QMessageBox.Warning)
        error.setStandardButtons(QMessageBox.Ok)
        error.setDetailedText(" Требования к ключу:\n"
                              "1) Ключ может состоять из: \n"
                              "- Латинского алфавита (а-я; А-Я)\n"
                              "- знаков препинания ('.', '!', '?', ',')\n"
                              "- пробелов\n"
                              "2) Длина ключа должна быть 9 символов\n"
                              "3) Если такой ключ уже существует, то будет выводиться ошибка!\n"
                              ""
                              "Требования к тексту: \n"
                              "1) текст может состоять из тех же символов, что и ключ\n"
                              "2) текст не должен быть пустым\n"
                              )
        error.exec_()

    def dencrypt(self):
        key_file = self.key_file.text()
        denc_text = get_coding_text(key_file)
        key_text = key_file.split('-')
        if denc_text == False:
            self.error_key_dencrypt()
        else:
            denc_text = convert_text_to_digits(denc_text, 'text')
            decode_text = decode(denc_text, key_text, 'text')
            self.dencrypt_text.setText(decode_text)


    def error_key_dencrypt(self):
        error = QMessageBox()
        error.setWindowTitle("Ошибка\t\t\t\t\t")
        error.setText("Введен неверный ключ.")
        error.setIcon(QMessageBox.Warning)
        error.setStandardButtons(QMessageBox.Ok)
        error.exec_()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = Login()
    new_ac_window = Registration()
    account_window = Personal_account()
    widget = QtWidgets.QStackedWidget()
    widget.addWidget(login_window)
    widget.addWidget(new_ac_window)
    widget.show()
    sys.exit(app.exec_())


