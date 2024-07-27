import base64
import os
import shutil
import tempfile

import flet as ft
from flet_core import FilePickerUploadFile, ElevatedButton, Ref
import pcap_parser

# 定义全局变量来存储 codec 和 result
result = tuple()
import os
import sys
import uuid

from pydub import AudioSegment


def main(page: ft.Page):
    # 软件标题
    page.title = "pacp 转化 3gp 音频"
    os.environ["FLET_SECRET_KEY"] = os.urandom(12).hex()

    def to_mp3(audio_file):
        # 加载3GA文件
        # 设置 ffmpeg 可执行文件的路径
        FFMPEG_PATH = os.path.join(os.getcwd(), "ffmpeg", "bin", "ffmpeg.exe")
        if not os.path.exists(FFMPEG_PATH):
            raise FileNotFoundError(FFMPEG_PATH)
        if not os.path.exists(audio_file):
            raise FileNotFoundError(audio_file)
        # # 配置 pydub 使用指定的 ffmpeg 路径
        os.environ["PATH"] += os.pathsep + os.path.dirname(FFMPEG_PATH)
        audio = AudioSegment.from_file(audio_file)
        # # 导出为MP3文件
        uuid_str = str(uuid.uuid4())
        audio.export(f"./assets/{uuid_str}.mp3", format="mp3")
        print("转换完成！")
        return uuid_str

    # upload_button.current.disabled = False
    # 上传完文件的结果
    def pick_files_result(e: ft.FilePickerResultEvent):
        global result
        # 上传完文件的结果
        selected_files.value = (
            ", ".join(map(lambda f: f.name, e.files)) if e.files else "上传取消!"
        )
        if not len(e.files):
            return
        file = e.files[0]
        print(file.name, file.size, file.path)
        selected_files.update()
        # 开始转换
        packets = pcap_parser.rdpcap(file.path)  # read packets from pcap or pcapng file
        codec = pcap_parser.guessCodec(packets, 'ietf')
        result = (packets, codec,)

    def save_files_result(e: ft.FilePickerResultEvent):
        # 保存文件结果
        print(e.path)
        file_path = e.path + '.mp3'  # 创建完整文件路径
        if not result:
            print("Empty or invalid input file (not mp3?)")
            return
        codec = result[1]
        packets = result[0]
        num_frames = 0
        seq = -1
        temp_file_path = None
        num_valid_frames = 0  # Number of frames of the first RTP flow in the trace. Should be the same as num_frames if there is only one RTP flow in the trace
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
        mp3_file = to_mp3(ofile.name)
        # 移动文件mp3_file到 file_path
        shutil.move(os.path.join("assets", mp3_file + ".mp3", ), file_path)
        # 删除临时文件
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        print("done")

    # 第一行字
    title = ft.Text()
    title.value = "请上传文件 :"
    # 添加文件选择器
    pick_files_dialog = ft.FilePicker(on_result=pick_files_result)
    # 添加文件保存器
    save_file_dialog = ft.FilePicker(on_result=save_files_result)

    # 选择文件的结果
    selected_files = ft.Text()
    # 将文件选择器放到最上层
    page.overlay.append(pick_files_dialog)
    page.overlay.append(save_file_dialog)

    page.add(
        ft.Column(
            [title,
             ft.ElevatedButton(
                 "上传文件",
                 icon=ft.icons.UPLOAD_FILE,
                 on_click=lambda _: pick_files_dialog.pick_files(
                     allow_multiple=False,
                     allowed_extensions=['pcap']
                 ),
             ), ft.ElevatedButton(
                "保存文件",
                icon=ft.icons.SAVE,
                on_click=lambda _: save_file_dialog.save_file(
                    allowed_extensions=['mp3']
                ),
            ),
             selected_files,
             ]
        )
    )


ft.app(target=main, assets_dir="assets", upload_dir="assets/uploads", view=ft.FLET_APP_WEB)
