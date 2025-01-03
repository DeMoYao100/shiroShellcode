import idaapi
import ida_kernwin
from PyQt5 import QtWidgets, QtCore, QtGui
from keystone import Ks, KS_ARCH_X86, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_MIPS, KS_ARCH_PPC, KS_ARCH_SPARC, KS_MODE_64, \
    KS_MODE_32, KS_MODE_LITTLE_ENDIAN, KS_MODE_THUMB, KS_MODE_MIPS64, KS_MODE_MIPS32, KS_MODE_PPC32, KS_MODE_BIG_ENDIAN
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS, CS_ARCH_PPC, CS_ARCH_SPARC, CS_MODE_64, \
    CS_MODE_32, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, CS_MODE_MIPS64, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
from PyQt5.QtCore import QTimer
import binascii
import re
import ida_segment
import os
import tkinter as tk
from tkinter import filedialog
import ida_bytes
import idc
import ida_nalt
import idautils


def ask_file(save, prompt, filetypes=[("All Files", "*.*")]):
    """
    Custom file dialog for selecting or saving a file.
    :param save: Boolean, True for saving a file, False for opening a file.
    :param prompt: Dialog prompt string.
    :param filetypes: List of file type filters for the dialog.
    :return: Selected file path or None if canceled.
    """
    # Create a hidden Tkinter root window
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)  # Bring the dialog to the front

    if save:
        file_path = filedialog.asksaveasfilename(title=prompt, filetypes=filetypes)
    else:
        file_path = filedialog.askopenfilename(title=prompt, filetypes=filetypes)

    root.destroy()
    return file_path

def find_changed_bytes():
    """Find bytes in the IDB that have been modified."""
    changed_bytes = []

    seg = ida_segment.get_first_seg()
    while seg:
        ea = seg.start_ea
        while ea < seg.end_ea:
            if ida_bytes.is_loaded(ea):
                byte = ida_bytes.get_byte(ea)
                original_byte = idaapi.get_original_byte(ea)
                if byte != original_byte:
                    changed_bytes.append((ea, byte, original_byte))
            ea += 1
        seg = ida_segment.get_next_seg(seg.start_ea)

    return changed_bytes

def patch_file(original_file, changed_bytes):
    """Patch a new file with modified bytes."""
    # Read the original file into memory
    try:
        with open(original_file, 'rb') as f:
            data = bytearray(f.read())
    except Exception as e:
        # print(f"Error reading original file: {e}")
        return

    # Apply the changes
    for ea, byte, original_byte in changed_bytes:
        file_offset = idaapi.get_fileregion_offset(ea)
        if file_offset != -1:
            data[file_offset] = byte
            # print(f'Patched: 0x{file_offset:X} with 0x{byte:02X} (original: 0x{original_byte:02X})')
        else:
            # print(f"Skipping EA {ea:X}: No file offset found.")
            pass

    # Ask the user for a new file path
    patched_file = ask_file(True, 'Choose new file to save patched data', [("Binary Files", "*.bin"), ("All Files", "*.*")])
    if patched_file:
        try:
            os.makedirs(os.path.dirname(patched_file), exist_ok=True)
            with open(patched_file, 'wb') as f:
                f.write(data)
            # print(f"Patched file saved to: {patched_file}")
        except Exception as e:
            # print(f"Error saving patched file: {e}")
            pass
    else:
        # print("No file selected for saving.")
        pass

def save_button_connect():
    # print('Finding changed bytes...')
    changed_bytes = find_changed_bytes()
    # print(f'done. {len(changed_bytes)} changed bytes found')

    if changed_bytes:
        original_file = idaapi.get_input_file_path()
        # print(f'Original file: {original_file}')

        if not os.path.exists(original_file):
            original_file = ask_file(False, 'Select original file to patch', [("Binary Files", "*.*"), ("All Files", "*.*")])

        if os.path.exists(original_file):
            patch_file(original_file, changed_bytes)
        else:
            # print('No valid file to patch provided')
            pass
    else:
        # print('No changes to patch')
        pass

def get_image_base():
    """
    获取 IDA 加载的最低地址（基地址）
    """
    return ida_nalt.get_imagebase()


def get_symbol_address(symbol_name):
    """
    获取 ELF 文件中指定符号的地址
    """
    for symbol_ea, name in idautils.Names():  # Names() 返回符号地址和名称的迭代器
        if name == symbol_name:
            return symbol_ea
    return None


class mapping():
    a_string = ''
    b_string = ''
    a_input_string = ''  # 预留需求，如果不需要自动格式化的话可能需要
    b_input_string = ''
    a: list[str] = []
    b: list[str] = []
    address = get_image_base()
    # 这组用来idx
    a_start = []
    b_start = []
    a_end = []
    b_end = []
    a_key_idx: list[int] = []
    b_key_idx: list[int] = []
    a_zip: list = list(zip(a_key_idx, a_start, a_end))
    b_zip: list = list(zip(b_key_idx, b_start, b_end))

    b_start_idx = 0
    b_end_idx = 0
    a_start_idx = 0
    a_end_idx = 0

    def __init__(self):
        self.address = get_image_base()
        pass

    def clear(self):
        self.a_string = ''
        self.b_string = ''
        self.a_start = []
        self.b_start = []
        self.a_end = []
        self.b_end = []
        self.a_key_idx = []
        self.b_key_idx = []
        self.a_zip = []
        self.b_zip = []
        self.b_start_idx = 0
        self.b_end_idx = 0
        self.a_start_idx = 0
        self.a_end_idx = 0

    def preprocess_instructions(self, instructions):
        """
        预处理指令，解析符号，仅替换外部符号，保留自定义标签
        """
        labels = set()  # 存储自定义标签
        processed_lines = []
        base_address = self.address
        # 首先扫描一遍，记录所有标签
        for line in instructions:
            line = line.rstrip()  # 保留行尾空格
            if not line:
                processed_lines.append("")  # 保留空行
                continue

            if line.endswith(":"):  # 标签定义
                label_name = line[:-1]
                labels.add(label_name)
                processed_lines.append(line)  # 标签直接保留
            else:
                processed_lines.append("")  # 保留结构和位置

        # 替换指令中的外部符号
        result = []
        for line in instructions:
            line = line.rstrip()  # 保留行尾空格
            if not line or line.endswith(":"):
                result.append(line)  # 空行和标签直接保留
                continue

            parts = line.split(maxsplit=1)
            instruction_type = parts[0]
            target = parts[1] if len(parts) > 1 else None

            # 如果目标是自定义标签，保持原样
            if target in labels or target is None:
                result.append(line)
            else:
                # 尝试解析符号地址
                symbol_address = get_symbol_address(target)
                if symbol_address is not None:
                    processed_line = f"{instruction_type} {hex(symbol_address)}"
                    result.append(processed_line)
                else:
                    # print(f"[!] 未找到符号或无效的目标: {target}")
                    result.append(line)  # 无法解析时，保留原指令

        # 将预处理结果组装为字符串，保持原始的换行符和空格
        return "\n".join(result)

    def get_mapping_a_to_b(self, start_position, end_position):
        # print("start_position, end_position:", start_position, end_position)
        # print("self.a_zip:", self.a_zip)
        # print("self.b_zip:", self.b_zip)
        # print("self.a_string:", self.a_string)
        # print("self.b_string:", self.b_string)
        for i in range(len(self.a_zip)):
            if self.a_zip[i][1] == start_position:
                self.b_start_idx = self.b_zip[i][1]
            if i + 1 < len(self.a_zip):
                if self.a_zip[i][1] < start_position <= self.a_zip[i + 1][1]:
                    self.b_start_idx = self.b_zip[i + 1][1]
            if i + 1 < len(self.a_zip):
                if self.a_zip[i][2] <= end_position < self.a_zip[i + 1][2]:
                    self.b_end_idx = self.b_zip[i][2]
            elif i + 1 == len(self.a_zip):
                if self.a_zip[i][2] <= end_position:
                    self.b_end_idx = self.b_zip[i][2]
        # print(self.b_start_idx, self.b_end_idx)
        return self.b_start_idx, self.b_end_idx
        # return self.b_string[self.b_start_idx: self.b_end_idx]

    def get_mapping_b_to_a(self, start_position, end_position):
        for i in range(len(self.b_zip)):
            if self.b_zip[i][1] == start_position:
                self.a_start_idx = self.a_zip[i][1]
            if i + 1 < len(self.b_zip):
                if self.b_zip[i][1] < start_position <= self.b_zip[i + 1][1]:
                    self.a_start_idx = self.a_zip[i + 1][1]
            if i + 1 < len(self.a_zip):
                if self.b_zip[i][2] <= end_position < self.b_zip[i + 1][2]:
                    self.a_end_idx = self.a_zip[i][2]
            elif i + 1 == len(self.b_zip):
                if self.b_zip[i][2] <= end_position:
                    self.a_end_idx = self.a_zip[i][2]

        return self.a_start_idx, self.a_end_idx


class HexAsmConverterDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.a_b_maps = mapping()
        self.setWindowTitle("Hex <-> Asm Converter")
        self.setGeometry(300, 300, 600, 300)
        self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        self.setAttribute(QtCore.Qt.WA_DeleteOnClose, False)  # 防止自动删除
        self.setAttribute(QtCore.Qt.WA_QuitOnClose, False)  # 防止退出IDA

        layout = QtWidgets.QVBoxLayout()

        arch_layout = QtWidgets.QHBoxLayout()
        self.arch_select = QtWidgets.QComboBox()
        self.arch_select.addItems(["x86_64", "x86_32", "ARM", "ARM64", "MIPS", "MIPS64"])
        self.arch_select.currentIndexChanged.connect(self.update_architecture)
        arch_layout.addWidget(QtWidgets.QLabel("Select Architecture:"))
        arch_layout.addWidget(self.arch_select)
        layout.addLayout(arch_layout)

        # 标记是否正在处理中，避免死循环
        self.processing_selection = False

        # 光标位置
        self.last_left_cursor_pos_start = 0
        self.last_left_cursor_pos_end = 0
        self.last_right_cursor_pos_start = 0
        self.last_right_cursor_pos_end = 0

        # 创建左右文本框布局
        main_layout = QtWidgets.QHBoxLayout()
        self.hex_input = QtWidgets.QTextEdit(self)
        self.hex_input.setPlaceholderText("Enter Hex")

        self.asm_input = QtWidgets.QTextEdit(self)
        self.asm_input.setPlaceholderText("Enter Assembly")
        self.hex_input.setStyleSheet("""
            QTextEdit {
                selection-background-color: #ff5733;  /* 设置选中背景色 */
                selection-color: white;  /* 设置选中文本颜色 */
            }
        """)
        self.asm_input.setStyleSheet("""
            QTextEdit {
                selection-background-color: #ff5733;  /* 设置选中背景色 */
                selection-color: white;  /* 设置选中文本颜色 */
            }
        """)
        main_layout.addWidget(self.hex_input)
        main_layout.addWidget(self.asm_input)


        patcher_layout = QtWidgets.QHBoxLayout()
        # 切换按钮
        self.toggle_button = QtWidgets.QPushButton("patcher")
        self.toggle_button.clicked.connect(self.toggle_input_row)
        patcher_layout.addWidget(self.toggle_button)
        self.input_row_widget = QtWidgets.QWidget()
        self.input_row_layout = QtWidgets.QHBoxLayout(self.input_row_widget)
        self.address_input_field = QtWidgets.QLineEdit()
        self.address_input_field.setPlaceholderText("address")
        self.patch_button = QtWidgets.QPushButton("patch")
        self.apply_button = QtWidgets.QPushButton("apply to source file")
        self.save_button = QtWidgets.QPushButton("Save as")
        self.patch_button.clicked.connect(self.patch_button_clicked)
        self.apply_button.clicked.connect(self.apply_button_clicked)
        self.save_button.clicked.connect(self.save_button_clicked)
        self.input_row_layout.addWidget(self.address_input_field)
        self.input_row_layout.addWidget(self.patch_button)
        # self.input_row_layout.addWidget(self.apply_button)
        self.input_row_layout.addWidget(self.save_button)
        self.input_row_widget.setVisible(False)
        patcher_layout.addWidget(self.input_row_widget)
        self.log_label = QtWidgets.QLabel("")
        self.input_row_layout.addWidget(self.log_label)

        layout.addLayout(main_layout)
        layout.addLayout(patcher_layout)
        self.setLayout(layout)

        self.ks = None
        self.cs = None
        self.update_architecture()

        self.hex_input.textChanged.connect(self.on_left_text_changed)
        self.asm_input.textChanged.connect(self.on_right_text_changed)
        self.hex_input.selectionChanged.connect(self.on_left_selection_changed)
        self.asm_input.selectionChanged.connect(self.on_right_selection_changed)

        QTimer.singleShot(0, self.show)

    def toggle_input_row(self):
        # 切换输入行的可见性
        if self.input_row_widget.isVisible():
            self.input_row_widget.setVisible(False)
            self.toggle_button.setText("patcher")
        else:
            self.input_row_widget.setVisible(True)
            self.toggle_button.setText("hide patcher")
        # 调整窗口大小以适应内容
        self.adjustSize()

    def patch_button_clicked(self):
        address = self.address_input_field.text()
        address = int(address, 16)
        patch_bytes = self.a_b_maps.a_string.replace(' ', '').replace('\n', '')
        patch_bytes = [int(patch_bytes[i:i + 2], 16) for i in range(0, len(patch_bytes), 2)]
        for i in range(len(patch_bytes)):
            idc.patch_byte(address + i, patch_bytes[i])
        self.log_label.setText("patched")
        pass

    def apply_button_clicked(self):
        self.log_label.setText("applied")
        pass

    def save_button_clicked(self):
        save_button_connect()
        # self.log_label.setText("Saved to")
        pass

    def update_architecture(self):
        """更新选择的架构并重新初始化Keystone和Capstone"""
        self.hex_input.blockSignals(True)
        self.asm_input.blockSignals(True)

        self.hex_input.clear()
        self.asm_input.clear()

        arch = self.arch_select.currentText()

        if arch == "x86_64":
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        elif arch == "x86_32":
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        elif arch == "ARM":
            self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        elif arch == "ARM (Thumb)":
            self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        elif arch == "ARM64":
            self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        elif arch == "MIPS":
            self.ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)  # 使用默认模式，不设置小端
            self.cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        elif arch == "MIPS64":
            self.ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS64)  # 使用默认模式，不设置小端
            self.cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64)
        elif arch == "PPC":
            self.ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32)  # 使用默认模式
            self.cs = Cs(CS_ARCH_PPC, CS_MODE_32)

        self.hex_input.blockSignals(False)
        self.asm_input.blockSignals(False)

    def hex_to_asm(self, hex_text):
        # 将hex转换为asm，初始化a, b的映射
        if not hex_text:
            self.asm_input.clear()
            return
        hex_to_asm_a = []
        hex_to_asm_b = []
        try:
            code = bytes.fromhex(hex_text)
            for insn in self.cs.disasm(code, self.a_b_maps.address):
                hex_to_asm_b.append(f"{insn.mnemonic} {insn.op_str}\n")
                hex_to_asm_a.append(binascii.hexlify(insn.bytes).decode())
        except Exception as e:
            # asm_code = "Invalid hex input"
            pass
        self.a_b_maps.a, self.a_b_maps.b = hex_to_asm_a, hex_to_asm_b

        # 初始化转化的 string 以及索引
        self.a_b_maps.clear()
        self.a_b_maps.a_string = hex_text
        a_idx = 0
        start_idx = 0
        while True:
            start_idx = self.a_b_maps.a_string.find(self.a_b_maps.a[a_idx], start_idx)
            if start_idx == -1:
                break
            self.a_b_maps.a_start.append(start_idx)
            self.a_b_maps.a_key_idx.append(a_idx)
            start_idx += len(self.a_b_maps.a[a_idx])
            self.a_b_maps.a_end.append(start_idx)
            a_idx += 1
            if a_idx == len(self.a_b_maps.a):
                break
            if start_idx >= len(self.a_b_maps.a_string):
                break
        self.a_b_maps.a_zip = list(zip(self.a_b_maps.a_key_idx, self.a_b_maps.a_start, self.a_b_maps.a_end))

        b_idx = 0
        start_idx = 0
        self.a_b_maps.b_string = ''.join(self.a_b_maps.b)
        while True:
            start_idx = self.a_b_maps.b_string.find(self.a_b_maps.b[b_idx], start_idx)
            if start_idx == -1:
                break
            self.a_b_maps.b_start.append(start_idx)
            self.a_b_maps.b_key_idx.append(b_idx)
            start_idx += len(self.a_b_maps.b[b_idx])
            self.a_b_maps.b_end.append(start_idx)
            b_idx += 1
            if b_idx == len(self.a_b_maps.b):
                break
            if start_idx >= len(self.a_b_maps.b_string):
                break
        self.a_b_maps.b_zip = list(zip(self.a_b_maps.b_key_idx, self.a_b_maps.b_start, self.a_b_maps.b_end))
        # print("asm_to_hex:")
        # print("self.a_b_maps.a_zip", self.a_b_maps.a_zip)
        # print("self.a_b_maps.b_zip", self.a_b_maps.b_zip)

    def asm_to_hex(self, asm_text):
        # 将asm转换为hex，初始化a, b的映射
        if not asm_text:
            self.hex_input.clear()
            return
        asm_text_all = self.a_b_maps.preprocess_instructions(asm_text.splitlines())
        # print("base:", hex(get_image_base()))
        # print(asm_text_all)
        asm_to_hex_a = []
        asm_to_hex_b = []

        try:
            # 一次性汇编整个代码
            start_address = self.a_b_maps.address
            encoding, _ = self.ks.asm(asm_text_all, start_address)

            # 使用 Capstone 逐条反汇编以获取每条指令的信息
            disassembled = {insn.address: binascii.hexlify(insn.bytes).decode('utf-8')
                            for insn in self.cs.disasm(bytes(encoding), start_address)}

            current_address = start_address

            for line in asm_text_all.splitlines():
                stripped_line = line.strip()

                if stripped_line.replace(' ', '') == "":  # 空行
                    asm_to_hex_b.append(line)
                    asm_to_hex_a.append("")
                    continue

                if ':' in stripped_line:  # 标签行
                    asm_to_hex_b.append(line)
                    asm_to_hex_a.append("")
                    continue

                # 尝试从反汇编结果中找到对应的机器码
                hex_code = disassembled.get(current_address, None)
                if hex_code:
                    asm_to_hex_b.append(line)
                    asm_to_hex_a.append(f"{' '.join([hex_code[i:i + 2] for i in range(0, len(hex_code), 2)])}")
                    current_address += len(bytes.fromhex(hex_code))
        except Exception as e:
            # print(f"Error during assembly: {e}")
            return

        self.a_b_maps.a, self.a_b_maps.b = asm_to_hex_a, asm_to_hex_b
        # 初始化转化的 string 以及索引
        self.a_b_maps.clear()
        self.a_b_maps.b_string = asm_text_all
        b_idx = 0
        start_idx = 0
        while True:
            start_idx = self.a_b_maps.b_string.find(self.a_b_maps.b[b_idx], start_idx)
            if start_idx == -1:
                break
            self.a_b_maps.b_start.append(start_idx)
            self.a_b_maps.b_key_idx.append(b_idx)
            start_idx += len(self.a_b_maps.b[b_idx])
            self.a_b_maps.b_end.append(start_idx)
            b_idx += 1
            if b_idx == len(self.a_b_maps.b):
                break
            if start_idx >= len(self.a_b_maps.b_string):
                break
        self.a_b_maps.b_zip = list(zip(self.a_b_maps.b_key_idx, self.a_b_maps.b_start, self.a_b_maps.b_end))

        self.a_b_maps.a_string = ' '.join(self.a_b_maps.a)
        a_idx = 0
        start_idx = 0
        while True:
            start_idx = self.a_b_maps.a_string.find(self.a_b_maps.a[a_idx], start_idx)
            if start_idx == -1:
                break
            self.a_b_maps.a_start.append(start_idx)
            self.a_b_maps.a_key_idx.append(a_idx)
            start_idx += len(self.a_b_maps.a[a_idx])
            self.a_b_maps.a_end.append(start_idx)
            a_idx += 1
            if a_idx == len(self.a_b_maps.a):
                break
            if start_idx >= len(self.a_b_maps.a_string):
                break
        self.a_b_maps.a_zip = list(zip(self.a_b_maps.a_key_idx, self.a_b_maps.a_start, self.a_b_maps.a_end))
        # print("asm_to_hex:")
        # print("self.a_b_maps.a_zip", self.a_b_maps.a_zip)
        # print("self.a_b_maps.b_zip", self.a_b_maps.b_zip)

    def on_left_text_changed(self):
        """处理左侧输入框的文本变化"""
        if self.address_input_field.text() != '':
            self.a_b_maps.address = self.address_input_field.text()
            self.a_b_maps.address = int(self.a_b_maps.address, 16)
            # print("on_left_text_changed", self.a_b_maps.address)
        hex_text = self.hex_input.toPlainText().strip()
        hex_text = re.sub(r'[^0-9a-fA-F]', '', hex_text)
        hex_text = hex_text.replace(' ', '')
        if len(hex_text) % 2 == 0:
            hex_text = ' '.join([hex_text[i:i + 2] for i in range(0, len(hex_text), 2)])
            if hex_text != self.hex_input.toPlainText().strip():
                self.save_cursor()
                self.hex_input.setPlainText(hex_text)
                self.restore_cursor()
        # print("hex_text", hex_text)
        try:
            self.asm_input.blockSignals(True)
            self.hex_to_asm(hex_text)
            self.asm_input.blockSignals(False)
        except:
            return
        if not self.a_b_maps.a:
            return

        # 更新右侧文本
        self.asm_input.blockSignals(True)
        self.save_cursor()
        self.asm_input.setPlainText(self.a_b_maps.b_string)
        self.restore_cursor()
        self.asm_input.blockSignals(False)

    def on_right_text_changed(self):
        """处理右侧输入框的文本变化"""
        if self.address_input_field.text() != '':
            self.a_b_maps.address = self.address_input_field.text()
            self.a_b_maps.address = int(self.a_b_maps.address, 16)
            print("on_right_text_changed", self.a_b_maps.address)
        asm_text = self.asm_input.toPlainText().strip()
        try:
            self.hex_input.blockSignals(True)
            self.asm_to_hex(asm_text)
            self.hex_input.blockSignals(False)
        except:
            return
        if not self.a_b_maps.a:
            return

        self.hex_input.blockSignals(True)
        self.save_cursor()
        self.hex_input.setPlainText(self.a_b_maps.a_string)
        self.restore_cursor()
        self.hex_input.blockSignals(False)

    def restore_cursor(self):
        self.hex_input.textCursor().setPosition(self.last_left_cursor_pos_start)
        self.hex_input.textCursor().setPosition(min(self.last_left_cursor_pos_end, len(self.hex_input.toPlainText())),
                                                QtGui.QTextCursor.KeepAnchor)
        self.asm_input.textCursor().setPosition(self.last_right_cursor_pos_start)
        self.asm_input.textCursor().setPosition(min(self.last_right_cursor_pos_end, len(self.asm_input.toPlainText())),
                                                QtGui.QTextCursor.KeepAnchor)

    def save_cursor(self):
        left_start = self.hex_input.textCursor().selectionStart()
        left_end = self.hex_input.textCursor().selectionEnd()
        cursor_now = self.hex_input.textCursor().position()
        if left_start == cursor_now:
            left_start, left_end = left_end, left_start
        self.last_left_cursor_pos_start, self.last_left_cursor_pos_end = left_start, left_end
        right_start = self.asm_input.textCursor().selectionStart()
        right_end = self.asm_input.textCursor().selectionEnd()
        cursor_now = self.asm_input.textCursor().position()
        if right_start == cursor_now:
            right_start, right_end = right_end, right_start
        self.last_right_cursor_pos_start, self.last_right_cursor_pos_end = right_start, right_end

    def on_left_selection_changed(self):
        if self.processing_selection:
            return
        self.processing_selection = True
        try:
            self.save_cursor()
            left_start, left_end = self.last_left_cursor_pos_start, self.last_left_cursor_pos_end
            if left_start > left_end:
                left_start, left_end = left_end, left_start
            left_text = self.hex_input.toPlainText()

            selected_left = left_text[left_start:left_end]

            if selected_left:
                self.highlight_right_text(left_start, left_end)

        finally:
            self.processing_selection = False

    def on_right_selection_changed(self):
        if self.processing_selection:
            return
        self.processing_selection = True

        try:
            self.save_cursor()
            left_start, left_end = self.last_right_cursor_pos_start, self.last_right_cursor_pos_end
            if left_start > left_end:
                left_start, left_end = left_end, left_start

            left_text = self.asm_input.toPlainText()

            selected_left = left_text[left_start:left_end]

            if selected_left:
                self.highlight_left_text(left_start, left_end)

        finally:
            self.processing_selection = False

    def highlight_right_text(self, left_start, left_end):
        start_index, end_index = self.a_b_maps.get_mapping_a_to_b(left_start, left_end)
        cursor = self.asm_input.textCursor()
        cursor.setPosition(start_index)
        cursor.setPosition(end_index, QtGui.QTextCursor.KeepAnchor)
        self.asm_input.setTextCursor(cursor)

    def highlight_left_text(self, left_start, left_end):
        start_index, end_index = self.a_b_maps.get_mapping_b_to_a(left_start, left_end)
        cursor = self.asm_input.textCursor()
        cursor.setPosition(start_index)
        cursor.setPosition(end_index, QtGui.QTextCursor.KeepAnchor)

        self.hex_input.setTextCursor(cursor)


# 全局变量存储对话框引用以防止闪退
hex_asm_converter_dialog = None


class HexAsmConverterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Hex <-> Asm Converter Plugin"
    help = "Press Ctrl + Shift + S to open the converter"
    wanted_name = "Hex <-> Asm Converter"
    wanted_hotkey = "Ctrl+Shift+C"

    def init(self):
        # print("Hex <-> Asm Converter Plugin initialized.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        global hex_asm_converter_dialog
        if hex_asm_converter_dialog is None:  # 检查是否已存在实例
            hex_asm_converter_dialog = HexAsmConverterDialog()

        # 使用 execute_sync 保证事件循环的兼容性
        ida_kernwin.execute_sync(lambda: hex_asm_converter_dialog.show(), ida_kernwin.MFF_NOWAIT)
        ida_kernwin.execute_sync(lambda: hex_asm_converter_dialog.raise_(), ida_kernwin.MFF_NOWAIT)
        ida_kernwin.execute_sync(lambda: hex_asm_converter_dialog.activateWindow(), ida_kernwin.MFF_NOWAIT)

    def term(self):
        pass


def PLUGIN_ENTRY():
    return HexAsmConverterPlugin()
