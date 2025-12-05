import requests
import whois
import re
from urllib.parse import urlparse
import tldextract
import pandas as pd
import numpy as np
from datetime import datetime
import time
import json
import warnings
import os
import socket
from dotenv import load_dotenv
import difflib

# Для машинного обучения
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self, model_path='phishing_model.joblib'):
        """
        Инициализация детектора фишинговых сайтов
        """
        load_dotenv()
        self.model_path = model_path
        self.model = None
        
        # Топ-100 популярных доменов для белого списка (уменьшаем False Positives)
        self.whitelist = [
            'google.com', 'youtube.com', 'facebook.com', 'baidu.com', 'wikipedia.org',
            'yahoo.com', 'twitter.com', 'amazon.com', 'vk.com', 'yandex.ru',
            'instagram.com', 'linkedin.com', 'reddit.com', 'netflix.com', 'microsoft.com',
            'bing.com', 'twitch.tv', 'office.com', 'mail.ru', 'github.com',
            'stackoverflow.com', 'adobe.com', 'wordpress.org', 'tumblr.com', 'paypal.com'
        ]
        
        # Глобальный белый список (Immunity List) — эти домены никогда не будут считаться фишингом
        self.safe_domains = [
            'tbank.ru', 'tinkoff.ru', 'sberbank.ru', 'alfabank.ru', 'vtb.ru',
            'yandex.ru', 'vk.com', 'mail.ru', 'gosuslugi.ru',
            'google.com', 'youtube.com', 'whatsapp.com', 'telegram.org'
        ]
        
        # Черные списки
        self.known_phishing_domains = self.load_blacklist()
        self.load_or_train_model()
        
    def load_blacklist(self):
        """Загрузка списка известных фишинговых доменов"""
        base_list = [
            'example-phishing.com', 'faceb00k-login.com', 'paypa1-secure.com'
        ]
        if os.path.exists('blacklist.txt'):
            try:
                with open('blacklist.txt', 'r') as f:
                    external_list = [line.strip() for line in f if line.strip()]
                    base_list.extend(external_list)
            except:
                pass
        return list(set(base_list))
    
    def update_blacklists(self):
        """Обновление черных списков из внешних источников"""
        try:
            url = "https://openphish.com/feed.txt"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                new_domains = []
                for line in response.text.splitlines():
                    if line.strip():
                        try:
                            dom = tldextract.extract(line.strip()).registered_domain
                            if dom: new_domains.append(dom)
                        except: continue
                
                self.known_phishing_domains.extend(new_domains)
                self.known_phishing_domains = list(set(self.known_phishing_domains))
                
                with open('blacklist.txt', 'w') as f:
                    for d in self.known_phishing_domains:
                        f.write(f"{d}\n")
                return True
        except:
            return False
        
    def check_virustotal(self, url):
        """Проверка URL через VirusTotal API"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key: return {}
            
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": api_key}
            
            response = requests.get(api_url, headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats
        except:
            pass
        return {}

    def extract_url_features(self, url):
        """Извлечение признаков из URL с многоуровневой проверкой брендов"""
        features = {}
        parsed_url = urlparse(url)
        domain_info = tldextract.extract(url)
        registered_domain = domain_info.registered_domain.lower()
        domain_part = domain_info.domain.lower() # SLD

        # --- Level 0: Global Whitelist (Immunity) ---
        # Официальные домены, которые имеют иммунитет к проверкам
        OFFICIAL_DOMAINS = {
            'steam': ['steampowered.com', 'steamcommunity.com', 'steamgames.com', 'valvesoftware.com'],
            'google': ['google.com', 'youtube.com', 'blogspot.com', 'gmail.com', 'gstatic.com'],
            'tbank': ['tbank.ru', 'tinkoff.ru', 'tinkoffjournal.ru'],
            'sberbank': ['sberbank.ru', 'sber.ru'],
            'vtb': ['vtb.ru'],
            'alfabank': ['alfabank.ru'],
            'vk': ['vk.com'],
            'yandex': ['yandex.ru', 'ya.ru'],
            'gosuslugi': ['gosuslugi.ru'],
            'whatsapp': ['whatsapp.com'],
            'telegram': ['telegram.org', 't.me'],
            'discord': ['discord.com', 'discordapp.com', 'discord.gg'],
            'microsoft': ['microsoft.com', 'live.com', 'office.com', 'azure.com', 'windows.com'],
            'amazon': ['amazon.com', 'media-amazon.com', 'aws.amazon.com'],
            'apple': ['apple.com', 'icloud.com'],
            'paypal': ['paypal.com'],
            'netflix': ['netflix.com'],
            'instagram': ['instagram.com'],
            'facebook': ['facebook.com', 'fb.com'],
            'twitter': ['twitter.com', 't.co', 'x.com', 'twitter.com']
        }

        # Собираем все разрешенные домены в один сет для быстрого поиска
        all_safe_domains = set(self.safe_domains) # Наследуем из init если есть
        for domains in OFFICIAL_DOMAINS.values():
            all_safe_domains.update(domains)

        features['brand_in_domain'] = 0
        features['is_typosquatting'] = 0
        
        # Базовые признаки
        features['url_length'] = len(url)
        features['has_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_info.domain) else 0
        features['at_symbol'] = url.count('@')
        features['double_slash'] = url.count('//')
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'shorte.st', 't.co', 'is.gd', 'cli.gs']
        features['is_shortened'] = 1 if any(s in url for s in shorteners) else 0
        features['has_dash'] = 1 if '-' in domain_info.domain else 0
        features['subdomain_count'] = domain_info.subdomain.count('.') + 1 if domain_info.subdomain else 0
        features['domain_length'] = len(domain_info.domain)
        features['digit_ratio'] = sum(c.isdigit() for c in domain_info.domain) / len(domain_info.domain) if domain_info.domain else 0
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0

        # === LEVEL 0: IMMUNITY CHECK ===
        if registered_domain in all_safe_domains:
            # Если домен в белом списке - это легитимный бренд. 
            # Ставим brand_in_domain=1 (для статистики), но is_typosquatting=0
            features['brand_in_domain'] = 1 
            features['is_typosquatting'] = 0
            features['domain_age'] = self.get_domain_age(registered_domain)
            return features

        # === LEVEL 1: AGGRESSIVE BRAND SEARCH (Fuzzy + Substring) ===
        target_brands = [
            'steam', 'valve', 'discord', 'instagram', 'google', 'facebook', 'vk', 
            'telegram', 'whatsapp', 'netflix', 'roblox', 'twitch', 'amazon', 
            'apple', 'paypal', 'sberbank', 'vtb', 'tbank', 'alfabank'
        ]
        
        # Объединяем поддомен и домен для поиска (e.g., steam-login.com -> steam-login)
        # Но обычно ищем в SLD. Инструкция: "Проходи по домену".
        check_str = domain_part
        found_threat = False

        for brand in target_brands:
            if found_threat: break
            
            # A. Прямое вхождение подстроки (Substring)
            if brand in check_str:
                print(f"⚠️ ТАЙПОСКВОТТИНГ (Substring): Бренд '{brand}' найден в '{check_str}'")
                features['brand_in_domain'] = 1
                features['is_typosquatting'] = 1
                found_threat = True
                break
            
            # B. Нечеткий поиск (Fuzzy Sliding Window)
            # Если строка короче бренда минус 1 символ, нет смысла искать (слишком короткая)
            if len(check_str) < len(brand) - 1:
                continue

            window_size = len(brand)
            threshold = 0.70 # 70% сходства
            
            # Sliding window iteration
            # Например: check_str="sleam", brand="steam". len=5. range(1). window="sleam". ratio=0.8
            for i in range(len(check_str) - window_size + 1):
                window = check_str[i : i + window_size]
                
                # difflib ratio
                ratio = difflib.SequenceMatcher(None, brand, window).ratio()
                
                if ratio >= threshold:
                    print(f"⚠️ ТАЙПОСКВОТТИНГ (Fuzzy): '{window}' ~ '{brand}' (Ratio: {ratio:.2f})")
                    features['brand_in_domain'] = 1
                    features['is_typosquatting'] = 1
                    found_threat = True
                    break

        features['domain_age'] = self.get_domain_age(registered_domain)
        
        return features
    
    def get_domain_age(self, domain):
        """
        Получение возраста домена.
        ИСПРАВЛЕНИЕ: Если не удалось узнать возраст, считаем домен СТАРЫМ (безопасным).
        """
        if not domain: return 3650
        
        # Устанавливаем таймаут для сокетов, чтобы whois не висел
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3)
        
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                    return age_days
                elif isinstance(creation_date, str):
                    # Попытка парсинга строки, если whois вернул строку
                    try:
                        # Часто форматы бывают разные, но попробуем базовый ISO
                        cd = datetime.fromisoformat(str(creation_date).replace('Z', '+00:00'))
                        return (datetime.now() - cd).days
                    except:
                        pass
        except Exception:
            pass # Игнорируем любые ошибки whois
        finally:
            socket.setdefaulttimeout(old_timeout)
        
        # Default: 10 years (Safe assumption)
        return 3650
    
    def analyze_html_content(self, url):
        """Анализ HTML"""
        features = {'has_forms': 0, 'has_password_field': 0, 'form_action_external': 0, 
                   'script_count': 0, 'iframe_count': 0, 'phishing_keywords': 0}
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            features['has_forms'] = 1 if forms else 0
            
            if features['has_forms']:
                password_fields = soup.find_all('input', {'type': 'password'})
                features['has_password_field'] = 1 if password_fields else 0
                
                for form in forms:
                    action = form.get('action', '')
                    if action and not action.startswith(('#', '/')) and url not in action:
                        features['form_action_external'] = 1
                        break
            
            features['script_count'] = len(soup.find_all('script'))
            features['iframe_count'] = len(soup.find_all('iframe'))
            
            text = soup.get_text().lower()
            keywords = ['login', 'password', 'verify', 'account', 'secure', 'banking', 'update', 'confirm']
            features['phishing_keywords'] = sum(1 for k in keywords if k in text)
            
        except:
            pass
        return features
    
    def check_blacklist(self, url):
        try:
            domain = tldextract.extract(url).registered_domain
            if domain in self.known_phishing_domains: return True
            for d in self.known_phishing_domains:
                if domain.endswith("." + d): return True
        except: pass
        return False
        
    def check_whitelist(self, url):
        """Проверка по белому списку"""
        try:
            domain = tldextract.extract(url).registered_domain
            return domain in self.whitelist
        except: return False

    def load_or_train_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except:
                self.train_model()
        else:
            self.train_model()
    
    def train_model(self, dataset_path='phishing_dataset.csv'):
        # Логика обучения...
        try:
            df = None
            if os.path.exists('Training Dataset.csv'):
                # Try UCI format
                try:
                    df = pd.read_csv('Training Dataset.csv')
                    if 'Result' in df.columns: 
                        df['is_phishing'] = df['Result'].apply(lambda x: 1 if x == -1 else 0)
                except: pass
                
            if df is None:
                # Генерация более качественного синтетического датасета
                df = self.create_sample_dataset()
            
            joblib.dump(self.model, self.model_path)
            
        except Exception as e:
            print(f"Ошибка обучения: {e}")
    
    def create_sample_dataset(self):
        """
        Создание улучшенного синтетического датасета для снижения False Positives
        """
        data = []
        
        # Фишинг: короткая жизнь, маскировка под бренды, странные домены
        for _ in range(500):
            data.append({
                'url_length': np.random.randint(40, 100),
                'has_ip': np.random.choice([0, 1], p=[0.9, 0.1]),
                'at_symbol': np.random.choice([0, 1], p=[0.9, 0.1]),
                'double_slash': np.random.choice([0, 1], p=[0.8, 0.2]),
                'is_shortened': np.random.choice([0, 1], p=[0.8, 0.2]),
                'has_dash': np.random.choice([0, 1], p=[0.7, 0.3]),
                'subdomain_count': np.random.randint(1, 4),
                'domain_length': np.random.randint(10, 25),
                'digit_ratio': np.random.uniform(0.1, 0.4),
                'brand_in_domain': np.random.choice([0, 1], p=[0.5, 0.5]),
                'has_https': np.random.choice([0, 1], p=[0.4, 0.6]), # Фишинг часто без https или с let's encrypt
                'domain_age': np.random.randint(0, 30), # Фишинг почти всегда новый!
                'is_typosquatting': np.random.choice([0, 1], p=[0.6, 0.4]), # Часто тайпосквоттинг
                'is_phishing': 1
            })
            
        # Легитимные: долгая жизнь, https, чистые домены
        for _ in range(500):
            data.append({
                'url_length': np.random.randint(15, 60),
                'has_ip': 0,
                'at_symbol': 0,
                'double_slash': 0,
                'is_shortened': 0,
                'has_dash': np.random.choice([0, 1], p=[0.9, 0.1]), # Редко дефис
                'subdomain_count': np.random.randint(2, 3), # www.google.com
                'domain_length': np.random.randint(3, 15),
                'digit_ratio': np.random.uniform(0, 0.1),
                'brand_in_domain': 0, # Сам бренд - это хорошо, но признак brand_in_domain обычно ищет "google" в "google-login.com"
                'has_https': 1, # Почти всегда https
                'domain_age': np.random.randint(365, 5000), # Старые домены
                'is_typosquatting': 0, # Легитимные не тайпосквотят
                'is_phishing': 0
            })
            
        return pd.DataFrame(data)

    def predict_phishing(self, url):
        """
        Основная функция для предсказания фишинга
        """
        print(f"\n{'='*50}")
        print(f"Анализ ввода: {url}")
        print('='*50)
        
        # 1. Нормализация и Валидация
        # Если нет протокола, добавляем https
        if not url.startswith(('http://', 'https://')):
            target_url = 'https://' + url
        else:
            target_url = url

        # Проверка: Похоже ли это вообще на домен?
        try:
            extracted = tldextract.extract(target_url)
            # Проверяем, есть ли доменная зона (suffix) или это IP адрес
            is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", extracted.domain)
            
            # Если нет суффикса (например .com) и это не IP -> это не сайт
            if not extracted.suffix and not is_ip and extracted.domain != 'localhost':
                print("❌ Ошибка: Введенный текст не является валидным URL.")
                return {'error': 'Некорректный URL. Введите адрес сайта (например, google.com)'}
                
        except Exception as e:
            print(f"Ошибка валидации: {e}")
            return {'error': 'Ошибка проверки формата URL'}

        # Используем нормализованный URL для дальнейших проверок
        url = target_url 

        # 2. Whitelist Check
        if self.check_whitelist(url):
            print("✅ URL в белом списке надежных доменов.")
            return {
                'url': url, 'is_phishing': False, 'confidence': 0.0, 
                'risk_level': 'SAFE', 'reason': 'Whitelist'
            }

        # 3. VirusTotal Check (Critical Path)
        # Проверяем VT ДО всего остального (экономия ресурсов и самая точная база)
        try:
            vt_stats = self.check_virustotal(url)
            vt_malicious = vt_stats.get('malicious', 0)
            vt_suspicious = vt_stats.get('suspicious', 0)
            
            if vt_malicious >= 1 or vt_suspicious >= 2:
                print(f"⚠️ GLOBAL THREAT: VirusTotal flagging found (Malicious: {vt_malicious}, Suspicious: {vt_suspicious})")
                return {
                    'url': url,
                    'is_phishing': True,
                    'confidence': 1.0,
                    'risk_level': 'CRITICAL',
                    'reason': 'Global Threat Database Match (VirusTotal)',
                    'features': {},
                    'vt_stats': vt_stats
                }
        except Exception as e:
            print(f"Ошибка VirusTotal: {e}")
            vt_stats = {}

        # 4. Features & Local Analysis
        try:
            url_features = self.extract_url_features(url)
            html_features = self.analyze_html_content(url)
            all_features = {**url_features, **html_features}
            
            # KILL SWITCH: Если тайпосквоттинг, то сразу ФИШИНГ (100% Risk)
            if all_features.get('is_typosquatting', 0) == 1:
                print(f"🔴 ФИШИНГ (Kill Switch: Typosquatting detected)")
                return {
                    'url': url,
                    'is_phishing': True,
                    'confidence': 1.0,
                    'risk_level': 'CRITICAL',
                    'reason': 'Typosquatting Detected',
                    'features': all_features,
                    'vt_stats': vt_stats
                }
            
            # Model Predict
            feature_names = [
                'url_length', 'has_ip', 'at_symbol', 'double_slash', 'is_shortened',
                'has_dash', 'subdomain_count', 'domain_length', 'digit_ratio',
                'brand_in_domain', 'has_https', 'domain_age', 'is_typosquatting'
            ]
            
            row = []
            for f in feature_names:
                row.append(all_features.get(f, 0))
            
            X = pd.DataFrame([row], columns=feature_names)
            
            confidence = 0
            is_phishing = False
            
            if self.model:
                try:
                    prob = self.model.predict_proba(X)[0]
                    is_phishing = prob[1] > 0.5
                    confidence = prob[1]
                except: pass
            
            # Эвристическая коррекция
            # Если домен очень старый, снижаем вероятность фишинга
            if all_features.get('domain_age', 0) > 365:
                confidence = min(confidence, 0.4) # Hard cap for widely trusted age
                if confidence < 0.5: is_phishing = False

            risk = "LOW"
            if confidence > 0.8: risk = "CRITICAL"
            elif confidence > 0.6: risk = "HIGH"
            elif confidence > 0.4: risk = "MEDIUM"

            if is_phishing:
                print(f"🔴 ФИШИНГ (Confidence: {confidence:.2%})")
            else:
                print(f"🟢 SAFE (Confidence: {confidence:.2%})")

            return {
                'url': url,
                'is_phishing': bool(is_phishing),
                'confidence': float(confidence),
                'risk_level': risk,
                'features': all_features,
                'vt_stats': vt_stats
            }
            
        except Exception as e:
            print(f"Ошибка анализа: {e}")
            return {'url': url, 'error': str(e), 'is_phishing': False, 'risk_level': 'UNKNOWN', 'confidence': 0}
