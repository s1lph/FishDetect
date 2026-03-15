import asyncio
import os
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import Message
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from phishing_detector import PhishingDetector
from result_formatter import format_result_for_telegram
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
if not BOT_TOKEN:
    raise ValueError("TELEGRAM_BOT_TOKEN не найден в переменных окружения. Добавьте его в .env файл")

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

detector = PhishingDetector()


@dp.message(Command("start"))
async def cmd_start(message: Message):
    welcome_text = (
        "<b>safenet</b>\n"
        "👋 Добро пожаловать в безопасный интернет\n\n"
        "Я помогаю проверить домены и URL на наличие признаков фишинга и других угроз"
        "Просто отправьте мне ссылку для проверки"
    )
    await message.answer(welcome_text)


@dp.message(Command("help"))
async def cmd_help(message: Message):
    help_text = (
        "📖 <b>Справка по использованию бота</b>\n\n"
        "🔍 <b>Проверка домена:</b>\n"
        "Отправьте домен или URL, который хотите проверить. Бот автоматически:\n"
        "1. Покажет статус проверки\n"
        "2. Проанализирует домен\n"
        "3. Выдаст вердикт и детальные результаты\n\n"
        "📋 <b>Команды:</b>\n"
        "/start - Запустить бота\n"
        "/help - Показать эту справку\n\n"
        "⚠️ <b>Важно:</b> Бот проверяет домены на основе множества факторов:\n"
        "• Возраст домена\n"
        "• Наличие HTTPS\n"
        "• Тайпосквоттинг\n"
        "• Базы данных угроз\n"
        "• И другие признаки фишинга"
    )
    await message.answer(help_text)


@dp.message()
async def check_domain(message: Message):
    url = message.text.strip()
    
    if not url:
        await message.answer("❌ Пожалуйста, отправьте домен или URL для проверки.")
        return
    
    status_msg = await message.answer("🔍 <b>Проверка в процессе...</b>\n\nАнализирую домен...")
    
    try:
        result = detector.predict_phishing(url)
        
        if 'error' in result:
            await status_msg.edit_text(
                f"❌ <b>Ошибка проверки</b>\n\n"
                f"{result['error']}\n\n"
                f"Пожалуйста, убедитесь, что вы отправили корректный домен или URL."
            )
            return
        
        formatted_result = format_result_for_telegram(result)
        await status_msg.edit_text(formatted_result)
        
    except Exception as e:
        error_text = (
            f"❌ <b>Произошла ошибка при проверке</b>\n\n"
            f"Ошибка: {str(e)}\n\n"
            f"Пожалуйста, попробуйте позже или проверьте корректность отправленного домена."
        )
        await status_msg.edit_text(error_text)


async def main():
    print("Запуск Telegram бота...")
    
    try:
        bot_info = await bot.get_me()
        print(f"Бот инициализирован: @{bot_info.username}")
        print("Подключение к Telegram API успешно!")
    except Exception as e:
        print(f"Ошибка подключения к Telegram API: {e}")
        print("Проверьте:")
        print("1. Правильность токена в файле .env")
        print("2. Наличие интернет-соединения")
        print("3. Доступность Telegram API")
        await bot.session.close()
        return
    
    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nБот остановлен пользователем")
    except Exception as e:
        print(f"Критическая ошибка при запуске бота: {e}")
        import traceback
        traceback.print_exc()
