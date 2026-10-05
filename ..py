import asyncio
import logging
import aiohttp
from datetime import datetime

# Loglama Yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("cyber_bot.log"), logging.StreamHandler()]
)

CONFIG = {
    "TELEGRAM_BOT_TOKEN": "YOUR_BOT_TOKEN",
    "TELEGRAM_CHAT_ID": "YOUR_CHAT_ID",
    "CISA_KEV_URL": "https://cisa.gov",
    "CHECK_INTERVAL": 1800  # 30 dakika
}

class CyberResearchBot:
    def __init__(self):
        self.session = None
        self.seen_cves = set() # Gerçek projede bunu veri tabanında (SQLite) tutmalısınız.

    async def init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def send_notification(self, message: str):
        url = f"https://telegram.org{CONFIG['TELEGRAM_BOT_TOKEN']}/sendMessage"
        payload = {"chat_id": CONFIG["TELEGRAM_CHAT_ID"], "text": message, "parse_mode": "Markdown"}
        try:
            async with self.session.post(url, json=payload) as response:
                if response.status != 200:
                    logging.error(f"Telegram bildirimi gönderilemedi: {response.status}")
        except Exception as e:
            logging.error(f"Telegram bağlantı hatası: {e}")

    async def fetch_cisa_vulnerabilities(self):
        """CISA Bilinen İstismar Edilen Zafiyetler Listesini Takip Eder"""
        logging.info("CISA KEV Veritabanı kontrol ediliyor...")
        try:
            async with self.session.get(CONFIG["CISA_KEV_URL"]) as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    # Son eklenen zafiyetleri kontrol et (Örnek amaçlı son 3)
                    for vuln in vulnerabilities[-3:]:
                        cve_id = vuln.get("cveID")
                        if cve_id not in self.seen_cves:
                            self.seen_cves.add(cve_id)
                            
                            report = (
                                f"🚨 *KRİTİK ZAFİYET TESPİT EDİLDİ (CISA KEV)*\n\n"
                                f"🆔 *CVE:* {cve_id}\n"
                                f"🏢 *Ürün:* {vuln.get('vendorProject')} - {vuln.get('product')}\n"
                                f"⚠️ *Açıklama:* {vuln.get('shortDescription')}\n"
                                f"🎯 *Çözüm/Eylem:* {vuln.get('requiredAction')}\n"
                            )
                            await self.send_notification(report)
        except Exception as e:
            logging.error(f"CISA KEV çekilirken hata oluştu: {e}")

    async def start_hunting(self):
        await self.init_session()
        logging.info("Siber Güvenlik Araştırmacı Botu Aktif Edildi.")
        
        while True:
            # Aynı anda birden fazla istihbarat kaynağını asenkron çalıştırabiliriz
            await asyncio.gather(
                self.fetch_cisa_vulnerabilities(),
                # buraya async_check_github(), async_check_shodan() gibi fonksiyonlar eklenebilir
            )
            logging.info(f"Tarama tamamlandı. {CONFIG['CHECK_INTERVAL']} saniye bekleniyor...")
            await asyncio.sleep(CONFIG["CHECK_INTERVAL"])

if __name__ == "__main__":
    bot = CyberResearchBot()
    try:
        asyncio.run(bot.start_hunting())
    except KeyboardInterrupt:
        logging.info("Bot kullanıcı tarafından durduruldu.")
