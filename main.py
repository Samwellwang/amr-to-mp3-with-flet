import base64
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Optional

import flet as ft
from flet_core import FilePickerUploadFile, ElevatedButton, Ref
import pcap_parser

import os
import uuid

from pydub import AudioSegment


class FileResult:
    def __init__(self):
        self.filename = None
        self.filesize = None
        self.filetype = None
        self.filename_without_extension = None


def main(page: ft.Page):
    # 软件标题
    page.window.width = 500
    page.window.height = 300
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.title = "转化AMR音频"
    os.environ["FLET_SECRET_KEY"] = os.urandom(12).hex()
    result_file = FileResult()
    menu_bar = ft.Row(
        controls=[
            ft.Text("文件(F)", style=ft.TextStyle(color="black", size=14)),
            ft.Text("  操作(A)", style=ft.TextStyle(color="black", size=14)),
            ft.Text("  查看(V)", style=ft.TextStyle(color="black", size=14)),
            ft.Text("  帮助(H)", style=ft.TextStyle(color="black", size=14)),
        ],
        alignment=ft.MainAxisAlignment.START,
        spacing=10
    )
    page.appbar = menu_bar

    def to_mp3(audio_file):
        # 加载3GA文件
        # 设置 ffmpeg 可执行文件的路径
        BASE_DIR = Path(__file__).resolve().parent
        ASSETS_DIR = os.path.join(BASE_DIR, 'assets')
        FFMPEG_PATH = os.path.join(ASSETS_DIR, "ffmpeg","bin", 'ffmpeg.exe')
        if not os.path.exists(FFMPEG_PATH):
            raise FileNotFoundError(FFMPEG_PATH)
        os.environ["PATH"] += os.pathsep + os.path.dirname(FFMPEG_PATH)
        if not os.path.exists(audio_file):
            raise FileNotFoundError(audio_file)
        # # 配置 pydub 使用指定的 ffmpeg 路径
        audio = AudioSegment.from_file(audio_file)
        # # 导出为MP3文件
        uuid_str = str(uuid.uuid4())
        audio.export(f"./assets/{uuid_str}.mp3", format="mp3")
        print("转换完成！")
        return uuid_str

    # upload_button.current.disabled = False
    # 上传完文件的结果
    def pick_files_result(e: ft.FilePickerResultEvent):
        try:
            # 上传完文件的结果
            selected_files.value = (
                ", ".join(map(lambda f: f.name, e.files)) if e.files else "上传取消!"
            )
            if not e or not e.files:
                return
            file = e.files[0]
            print(file.name, file.size, file.path)
            selected_files.update()
            try:
                # 开始转换
                packets = pcap_parser.rdpcap(file.path)  # read packets from pcap or pcapng file
                codec = pcap_parser.guessCodec(packets, 'ietf')
            except Exception as e:
                print(e)
                result_txt.value = "源格式异常"
                result_txt.update()
                print_txt.value = ""
                print_txt.update()
                display.value = "转换失败"
                page.open(dlg)
                return
            num_frames = 0
            seq = -1
            num_valid_frames = 0  # Number of frames of the first RTP flow in the trace. Should be the same as num_frames if there is only one RTP flow in the trace
            os.makedirs("./assets", exist_ok=True)
            with tempfile.NamedTemporaryFile(suffix=".3ga", dir="./assets", mode="wb", delete=False) as ofile:
                temp_file_path = ofile.name
                if codec == 'amr':
                    ofile.write("#!AMR\n".encode())
                elif codec == 'amr-wb':
                    ofile.write("#!AMR-WB\n".encode())
                else:
                    ofile.write("#!EVS_MC1.0\n".encode())
                    ofile.write(b'\x00\x00\x00\x01')
                for packet in packets:
                    isvalid = False
                    num_frames += 1
                    rtp = pcap_parser.getRtpAsPacket(packet)
                    if rtp == None:
                        continue
                    if seq == -1:  # first RTP packet
                        seq = rtp.sequence
                        syncsrcid = rtp.sourcesync
                        ptype = rtp.payload_type
                        isvalid = True
                    elif seq != rtp.sequence and syncsrcid == rtp.sourcesync and ptype == rtp.payload_type:
                        isvalid = True
                    if isvalid == True:
                        num_valid_frames += 1
                        if 'ietf' == 'ietf':
                            pcap_parser.storePayloadIetf(ofile, codec, rtp.load)
                        else:
                            pcap_parser.storePayloadIu(ofile, codec, rtp.load)
            print("转化3ga完成")
            print_txt.value = "转化3ga完成"
            print_txt.update()
            mp3_result = to_mp3(temp_file_path)
            print("转换MP3完成")
            print_txt.value = "转换MP3完成"
            print_txt.update()
            save_btn.disabled = False
            save_btn.update()
            result_txt.value = "转换成功"
            result_txt.update()
            result_file.filename = mp3_result
            # 删除临时文件
            if temp_file_path and os.path.exists(temp_file_path):
                os.remove(temp_file_path)
        except Exception as e:
            print(traceback.format_exc())
            print_txt.value = "失败" + str(e)
            print_txt.update()

    def save_files_result(e: ft.FilePickerResultEvent):
        # 保存文件结果
        print(e.path)
        file_path = e.path + '.mp3'  # 创建完整文件路径
        # 移动文件mp3_file到 file_path
        shutil.move(os.path.join("assets", result_file.filename + ".mp3", ), file_path)
        print("done")
        result_txt.value = f"文件保存在{file_path}"
        result_txt.update()
        display.value = "保存成功"
        page.open(dlg)

    # 添加文件选择器
    pick_files_dialog = ft.FilePicker(on_result=pick_files_result)
    # 添加文件保存器
    save_file_dialog = ft.FilePicker(on_result=save_files_result)
    # 选择文件的结果
    selected_files = ft.Text("转换结果")
    save_btn = ft.TextButton(
        disabled=True,
        text="保存文件",
        icon=ft.icons.SAVE,
        on_click=lambda _: save_file_dialog.save_file(
            allowed_extensions=['mp3']),
    )

    ## 显示结果
    result_txt = ft.Text("", weight=ft.FontWeight.BOLD)
    print_txt = ft.Text("", weight=ft.FontWeight.BOLD)
    display = ft.Text("default")
    dlg = ft.AlertDialog(
        title=display,
    )

    # 将文件选择器放到最上层
    page.overlay.append(pick_files_dialog)
    page.overlay.append(save_file_dialog)

    page.add(
        ft.Column(
            controls=[
                ft.Card(
                    content=ft.Container(
                        content=ft.Column(
                            [
                                ft.ListTile(
                                    leading=ft.Icon(ft.icons.ALBUM_OUTLINED),
                                    title=selected_files,
                                ),
                                ft.Row(
                                    controls=[
                                        ft.TextButton("播放", icon="PLAY_ARROW", disabled=True),
                                        save_btn
                                    ],
                                    alignment=ft.MainAxisAlignment.END,
                                ),
                            ]
                        ),
                        width=400,
                        height=100,
                        padding=10,
                    )
                ),
                ft.CupertinoButton(
                    bgcolor=ft.colors.RED,
                    content=ft.Text("上传文件"),
                    opacity_on_click=0.3,
                    on_click=lambda _: pick_files_dialog.pick_files(
                        allow_multiple=False,
                        allowed_extensions=['pcap']
                    ),
                    height=50,
                    width=400
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.END,
            adaptive=True
        ),
        result_txt,
        print_txt
    )


ft.app(target=main, assets_dir="assets", view=ft.FLET_APP)
