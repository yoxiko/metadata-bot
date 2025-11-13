

import os
import json
import asyncio
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message
from aiogram.filters import Command

from main import analyze_file_for_bot

BOT_TOKEN = "token"
DOWNLOAD_PATH = "downloads"
os.makedirs(DOWNLOAD_PATH, exist_ok=True)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def download_file(file_id: str, file_name: str) -> str:
    file = await bot.get_file(file_id)
    path = os.path.join(DOWNLOAD_PATH, f"{file_id}_{file_name}")
    await bot.download_file(file.file_path, path)
    return path

@dp.message(Command("start"))
async def cmd_start(message: Message):
    text = """
Metadata Analyzer Bot

Send any file to get JSON metadata analysis.

Supported: JPEG, PNG, PDF
    """
    await message.answer(text)

@dp.message(F.document)
async def handle_document(message: Message):
    try:
        doc = message.document
        
        # Скачивание
        file_path = await download_file(doc.file_id, doc.file_name or "file")
        
        # Анализ
        result = analyze_file_for_bot(file_path)
        
        # Очистка
        try:
            os.remove(file_path)
        except:
            pass
        
        # JSON вывод с код-форматированием
        result_json = json.dumps(result, indent=2, ensure_ascii=False)
        
        # Обязательное код-форматирование через Markdown
        formatted_message = f"```json\n{result_json}\n```"
        
        await message.answer(formatted_message, parse_mode="MarkdownV2")
            
    except Exception as e:
        await message.answer(f"Error: {str(e)}")

async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())