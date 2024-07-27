import os
import sys
import uuid

from pydub import AudioSegment


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