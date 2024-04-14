import os
import signal
import subprocess
import sys

from PyQt5.QtCore import QThread, Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont, QIntValidator
from PyQt5.QtWidgets import QApplication, QCheckBox, QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QInputDialog, \
    QLabel, QLineEdit, QListWidget, QPushButton, QSpacerItem, QTextBrowser, QVBoxLayout, QWidget


class CryptoscanThread(QThread):
    output_received = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.command = []
        self.stopped = False

    def set_command(self, command):
        self.command = command

    def run(self):
        try:
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = "1"
            if sys.platform == 'win32':
                self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                                bufsize=1, universal_newlines=True, env=env, encoding='utf8')
            else:
                self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                                bufsize=1, universal_newlines=True, env=env, encoding='utf8',
                                                preexec_fn=os.setsid)

            for line in iter(self.process.stdout.readline, ''):
                self.output_received.emit(line.rstrip('\n'))
                if self.stopped:
                    self.stop()
                    break

            for line in iter(self.process.stderr.readline, ''):
                self.output_received.emit(line.rstrip('\n'))
                if self.stopped:
                    self.stop()
                    break

            self.process.stdout.close()
            self.process.stderr.close()
            self.process.wait()

        except Exception as e:
            print(f"Error in CryptoscanThread: {e}")

    def stop(self):
        self.stopped = True
        if self.process:
            try:
                if sys.platform == 'win32':
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.process.pid)], check=True)
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except Exception as e:
                print(f"Failed to stop the process: {e}")


class CryptoscanGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.thread = CryptoscanThread()

        self.init_ui()
        self.run_help_command()

    def init_ui(self):
        self.title_label = QLabel('Cryptoscan GUI')
        self.title_font = QFont()
        self.title_font.setPointSize(16)
        self.title_font.setBold(True)
        self.title_label.setFont(self.title_font)
        self.title_label.setAlignment(Qt.AlignCenter)

        self.text_font = QFont()
        self.text_font.setPointSize(9)

        self.label_font = QFont()
        self.label_font.setBold(True)

        self.button_font = QFont()
        self.button_font.setBold(True)
        self.button_font.setPointSize(9)

        self.label_font_larger = QFont()
        self.label_font_larger.setBold(True)
        self.label_font_larger.setPointSize(10)

        self.label_font_larger_italic = QFont()
        self.label_font_larger_italic.setBold(True)
        self.label_font_larger_italic.setItalic(True)
        self.label_font_larger_italic.setPointSize(10)

        self.path_label = QLabel('Path:')
        self.path_label.setFont(self.label_font)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Select path")
        self.browse_button = QPushButton('Browse', clicked=self.browse_search_directory)
        self.browse_button.setFont(self.button_font)
        self.browse_button.setMaximumWidth(140)

        self.temp_path_label = QLabel('Temporary Path:')
        self.temp_path_label.setFont(self.label_font)
        self.temp_path_edit = QLineEdit()
        self.temp_path_edit.setPlaceholderText("Select temporary path")
        self.temp_browse_button = QPushButton('Browse Temp Path', clicked=self.browse_temp_directory)
        self.temp_browse_button.setFont(self.button_font)
        self.temp_browse_button.setMaximumWidth(180)

        self.optional_label = QLabel('Optional:')
        self.optional_label.setFont(self.label_font_larger_italic)
        self.optional_label.setAlignment(Qt.AlignCenter)

        self.xlsx_label = QLabel('Convert to XLSX:')
        self.xlsx_label.setFont(self.label_font)
        self.xlsx_label.setFixedWidth(162)
        self.xlsx_checkbox = QCheckBox()

        self.max_size_label = QLabel('Max File Size:')
        self.max_size_label.setFont(self.label_font)
        self.max_size_label.setFixedWidth(162)
        self.max_size_edit = QLineEdit()
        self.max_size_edit.setValidator(QIntValidator())
        self.max_size_edit.setMaximumWidth(80)
        self.size_unit_combobox = QComboBox()
        self.size_unit_combobox.addItems(['B', 'KB', 'MB', 'GB'])
        self.size_unit_combobox.setMaximumWidth(60)

        self.exclude_label = QLabel('Exclude Paths:')
        self.exclude_label.setFont(self.label_font)
        self.exclude_list = QListWidget()
        self.exclude_list.setMaximumHeight(100)
        self.add_path_button = QPushButton('Add Path', clicked=self.browse_and_add_path)
        self.add_path_button.setFont(self.button_font)
        self.add_path_button.setMaximumWidth(180)
        self.remove_path_button = QPushButton('Remove Selected Path', clicked=self.remove_selected_path)
        self.remove_path_button.setFont(self.button_font)
        self.remove_path_button.setMaximumWidth(190)

        self.run_button = QPushButton('Run Cryptoscan', clicked=self.run_stop_cryptoscan)
        self.run_button.setFont(self.button_font)
        self.run_button.setObjectName('runButton')
        self.run_button.setMaximumWidth(400)

        self.output_label = QLabel('Output:')
        self.output_label.setFont(self.label_font_larger)
        self.output_browser = QTextBrowser()
        self.output_browser.setFont(self.text_font)

        self.setStyleSheet(
            "QMainWindow {background: #333;} QPushButton {background-color: #4CAF50; color: white;} QPushButton:hover {background-color: #45a049;} QPushButton:pressed {background-color: darkred;}")

        layout = QVBoxLayout(self)

        self.add_widgets_to_layout(layout)
        self.setGeometry(100, 100, 1000, 950)
        self.setWindowTitle('Cryptoscan GUI')
        self.show()

    def add_widgets_to_layout(self, layout):
        spacer_layout = QSpacerItem(0, 20)

        title_layout = QVBoxLayout()
        title_layout.addWidget(self.title_label)

        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_label)
        path_layout.addWidget(self.path_edit)
        path_browse_layout = QHBoxLayout()
        path_browse_layout.addWidget(self.browse_button)

        optional_layout = QHBoxLayout()
        optional_layout.addWidget(self.optional_label)

        xlsx_checkbox_layout = QHBoxLayout()
        xlsx_checkbox_layout.addWidget(self.xlsx_label)
        xlsx_checkbox_layout.addWidget(self.xlsx_checkbox)
        xlsx_checkbox_layout.addStretch()

        max_size_layout = QHBoxLayout()
        max_size_layout.addWidget(self.max_size_label)
        max_size_layout.addWidget(self.max_size_edit)
        max_size_layout.addWidget(self.size_unit_combobox)
        max_size_layout.addStretch()

        exclude_layout = QHBoxLayout()
        exclude_layout.addWidget(self.exclude_label)
        exclude_layout.addWidget(self.exclude_list)

        exclude_layout_buttons = QHBoxLayout()
        exclude_layout_buttons.addStretch()
        exclude_layout_buttons.addWidget(self.add_path_button)
        exclude_layout_buttons.addWidget(self.remove_path_button)
        exclude_layout_buttons.addStretch()

        temp_path_layout = QHBoxLayout()
        temp_path_layout.addWidget(self.temp_path_label)
        temp_path_layout.addWidget(self.temp_path_edit)

        temp_path_layout_button = QHBoxLayout()
        temp_path_layout_button.addWidget(self.temp_browse_button)

        run_button_layout = QHBoxLayout()
        run_button_layout.addWidget(self.run_button)

        output_label_layout = QHBoxLayout()
        output_label_layout.addStretch()
        output_label_layout.addWidget(self.output_label)
        output_label_layout.addStretch()

        output_browser_layout = QHBoxLayout()
        output_browser_layout.addWidget(self.output_browser)

        optional_group_box = QGroupBox()
        optional_group_layout = QVBoxLayout()
        optional_group_layout.addLayout(xlsx_checkbox_layout)
        optional_group_layout.addLayout(max_size_layout)
        optional_group_layout.addLayout(exclude_layout)
        optional_group_layout.addLayout(exclude_layout_buttons)
        optional_group_layout.addLayout(temp_path_layout)
        optional_group_layout.addLayout(temp_path_layout_button)
        optional_group_box.setLayout(optional_group_layout)
        optional_group_box.setFixedHeight(300)
        optional_group_box.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid black;
                border-radius: 5px;
            }
        """)

        layout.addLayout(title_layout)
        layout.addLayout(path_layout)
        layout.addLayout(path_browse_layout)
        layout.addSpacerItem(spacer_layout)
        layout.addLayout(optional_layout)
        layout.addWidget(optional_group_box)
        layout.addSpacerItem(spacer_layout)
        layout.addLayout(run_button_layout)
        layout.addSpacerItem(spacer_layout)
        layout.addLayout(output_label_layout)
        layout.addLayout(output_browser_layout)

    def browse_search_directory(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Directory", options=QFileDialog.DontUseNativeDialog)
        if folder_path:
            self.path_edit.setText(folder_path)

    def browse_temp_directory(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Temporary Directory", options=QFileDialog.DontUseNativeDialog)
        if folder_path:
            self.temp_path_edit.setText(folder_path)

    def browse_and_add_path(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Directory", options=QFileDialog.DontUseNativeDialog)
        if folder_path:
            self.exclude_list.addItem(folder_path)

    def run_stop_cryptoscan(self):
        if self.thread.isRunning():
            self.thread.stopped = True
            self.run_button.setEnabled(False)
        else:
            self.thread.stopped = False
            self.run_button.setText('Stop Processing')
            self.run_button.setStyleSheet("background-color: red; color: white;")
            self.run_button.setEnabled(True)

            search_path = self.path_edit.text()
            use_max_size = self.max_size_edit.text()
            max_filesize = f"{use_max_size} {self.size_unit_combobox.currentText()}"
            excluded_paths = [self.exclude_list.item(i).text() for i in range(self.exclude_list.count())]
            temp_path = self.temp_path_edit.text()

            convert_to_xlsx = self.xlsx_checkbox.isChecked()

            command = [sys.executable, 'Cryptoscan.py', search_path]
            if use_max_size:
                command.extend(['--maxfilesize', max_filesize])
            if excluded_paths:
                command.extend(['--excludepaths'] + excluded_paths)
            if convert_to_xlsx:
                command.extend(['--xlsx'])
            if temp_path:
                command.extend(['--temppath', temp_path])

            self.thread.set_command(command)
            self.thread.start()
            self.thread.finished.connect(self.finish_processing)

    def add_path(self):
        path, ok = QInputDialog.getText(self, 'Add Exclude Path', 'Enter Path:')
        if ok and path:
            self.exclude_list.addItem(path)

    def remove_selected_path(self):
        list_items = self.exclude_list.selectedItems()
        if not list_items:
            return
        for item in list_items:
            self.exclude_list.takeItem(self.exclude_list.row(item))

    def finish_processing(self):
        self.run_button.setText('Run Cryptoscan')
        self.run_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.run_button.setObjectName('runButton')
        self.run_button.setEnabled(True)

    def run_help_command(self):
        command = [sys.executable, 'Cryptoscan.py', '--help']
        self.thread.set_command(command)
        self.thread.start()
        self.thread.finished.connect(self.finish_help_command)

    def finish_help_command(self):
        self.thread.output_received.disconnect(self.update_output_browser)
        self.thread.output_received.connect(self.update_output_browser_initial)
        self.thread.finished.disconnect(self.finish_help_command)

    @pyqtSlot(str)
    def update_output_browser(self, output_text):
        if not self.thread.stopped:
            self.output_browser.append(output_text)
            self.scroll_to_bottom()

    @pyqtSlot(str)
    def update_output_browser_initial(self, output_text):
        self.output_browser.append(output_text)
        self.scroll_to_bottom()

    def scroll_to_bottom(self):
        cursor = self.output_browser.textCursor()
        cursor.movePosition(cursor.End)
        self.output_browser.setTextCursor(cursor)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CryptoscanGUI()
    window.thread.output_received.connect(window.update_output_browser)
    sys.exit(app.exec_())
