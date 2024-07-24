import base64
import os

import flet as ft
from flet_core import FilePickerUploadFile, ElevatedButton, Ref

import pcap_parser

# 定义全局变量来存储 codec 和 result
result = tuple()
def main(page: ft.Page):
    # 软件标题
    page.title = "pacp 转化 3gp 音频"
    os.environ["FLET_SECRET_KEY"] = os.urandom(12).hex()
    upload_button = Ref[ElevatedButton]()
    # upload_button.current.disabled = False
    # 上传完文件的结果
    def pick_files_result(e: ft.FilePickerResultEvent):
        upload_button.current.disabled = True if e.files is None else False
        global result
        # 上传完文件的结果
        selected_files.value = (
            ", ".join(map(lambda f: f.name, e.files)) if e.files else "上传取消!"
        )
        if  not len(e.files):
            return
        file = e.files[0]
        print(file.name, file.size, file.path)
        # 开始转换
        # packets = pcap_parser.rdpcap(file.path)  # read packets from pcap or pcapng file
        # codec = pcap_parser.guessCodec(packets, 'ietf')
        # result = (packets,codec,)
        selected_files.update()
    def save_files_result(e: ft.FilePickerResultEvent):
        # 保存文件结果
        print(e.path)
        file_path = e.path+'.3ga' # 创建完整文件路径
        if not result:
            print("Empty or invalid input file (not pcap?)")
            return
        codec = result[1]
        packets = result[0]
        num_frames = 0
        seq = -1
        num_valid_frames = 0  # Number of frames of the first RTP flow in the trace. Should be the same as num_frames if there is only one RTP flow in the trace
        num_bad_frames = 0
        with open(file_path, 'wb') as ofile:
            # Write magic number to output file
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
                # rtp = RTP(packet[UDP].load)
                if seq == -1:  # first RTP packet
                    # print('DEBUG First packet content:')
                    # rtp.show()
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
        print("done")
    def upload_files(e):
        uf = []
        if pick_files_dialog.result is not None and pick_files_dialog.result.files is not None:
            for f in pick_files_dialog.result.files:
                uf.append(
                    FilePickerUploadFile(
                        f.name,
                        upload_url=page.get_upload_url(f.name, 6),
                    )
                )
            pick_files_dialog.upload(uf)
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
            [   title,
                ft.ElevatedButton(
                    "上传文件",
                    icon=ft.icons.UPLOAD_FILE,
                    on_click=lambda _: pick_files_dialog.pick_files(
                        allow_multiple=False,
                        allowed_extensions=['pcap']
                    ),
                ),ft.ElevatedButton(
                    "保存文件",
                    icon=ft.icons.SAVE,
                    on_click=lambda _: save_file_dialog.save_file(
                        allowed_extensions=['pcap']
                    ),
                ),ft.ElevatedButton(
                "Upload",
                ref=upload_button,
                icon=ft.icons.UPLOAD,
                on_click=upload_files,
                disabled=False,
                ),
                selected_files,
            ]
        )
    )

ft.app(target=main, assets_dir="assets", upload_dir="assets/uploads")