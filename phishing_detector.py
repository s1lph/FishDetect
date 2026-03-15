import requests
import whois
import re
from urllib.parse import urlparse
import tldextract
import pandas as pd
import numpy as np
from datetime import datetime
import warnings
import os
import socket
from dotenv import load_dotenv
import difflib
import threading
import joblib

warnings.filterwarnings('ignore')

class PhishingDetector:
    def __init__(self, model_path='phishing_model.joblib'):
        load_dotenv()
        self.model_path = model_path
        self.model = None
        
        self.whitelist = self.load_whitelist()
        self.known_phishing_domains = self.load_blacklist()
        self.load_or_train_model()
        
    def load_whitelist(self):
        if os.path.exists('whitelist.txt'):
            try:
                with open('whitelist.txt', 'r', encoding='utf-8') as f:
                    domains = [line.strip().lower() for line in f if line.strip() and not line.strip().startswith('#')]
                    return list(set(domains))
            except:
                pass
        return []
        
    def load_blacklist(self):
        if os.path.exists('blacklist.txt'):
            try:
                with open('blacklist.txt', 'r', encoding='utf-8') as f:
                    domains = [line.strip().lower() for line in f if line.strip() and not line.strip().startswith('#')]
                    return list(set(domains))
            except:
                pass
        return []
    
    def check_virustotal(self, url):
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
        features = {}
        parsed_url = urlparse(url)
        domain_info = tldextract.extract(url)
        registered_domain = domain_info.registered_domain.lower()
        domain_part = domain_info.domain.lower()

        all_safe_domains = set(self.whitelist)

        features['brand_in_domain'] = 0
        features['is_typosquatting'] = 0
        
        features['url_length'] = len(url)
        features['has_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_info.domain) else 0
        features['at_symbol'] = url.count('@')
        if url.startswith(('http://', 'https://')):
            protocol_end = url.find('://') + 3
            url_after_protocol = url[protocol_end:]
            features['double_slash'] = url_after_protocol.count('//')
        else:
            features['double_slash'] = url.count('//')
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'shorte.st', 't.co', 'is.gd', 'cli.gs']
        features['is_shortened'] = 1 if any(s in url for s in shorteners) else 0
        features['subdomain_count'] = domain_info.subdomain.count('.') + 1 if domain_info.subdomain else 0
        features['domain_length'] = len(domain_info.domain)
        features['digit_ratio'] = sum(c.isdigit() for c in domain_info.domain) / len(domain_info.domain) if domain_info.domain else 0
        features['has_https'] = 1 if parsed_url.scheme == 'https' else 0

        if registered_domain in all_safe_domains:
            features['brand_in_domain'] = 0 
            features['is_typosquatting'] = 0
            age_result = self.get_domain_age(registered_domain)
            if isinstance(age_result, tuple):
                features['domain_age'] = age_result[0]
                features['domain_age_display'] = age_result[1]
            else:
                features['domain_age'] = age_result
                features['domain_age_display'] = "Не определен"
            return features

        target_brands = [
            'steam', 'valve', 'discord', 'instagram', 'google', 'facebook', 'vk', 
            'telegram', 'whatsapp', 'netflix', 'roblox', 'twitch', 'amazon', 
            'apple', 'paypal', 'sberbank', 'vtb', 'tbank', 'alfabank'
        ]
        
        check_str = domain_part
        found_threat = False

        for brand in target_brands:
            if found_threat: break
            
            if brand in check_str:
                features['brand_in_domain'] = 1
                features['is_typosquatting'] = 1
                found_threat = True
                break
            
            if len(check_str) < len(brand) - 1:
                continue

            window_size = len(brand)
            threshold = 0.70
            
            for i in range(len(check_str) - window_size + 1):
                window = check_str[i : i + window_size]
                ratio = difflib.SequenceMatcher(None, brand, window).ratio()
                
                if ratio >= threshold:
                    features['brand_in_domain'] = 1
                    features['is_typosquatting'] = 1
                    found_threat = True
                    break

        age_result = self.get_domain_age(registered_domain)
        if isinstance(age_result, tuple):
            features['domain_age'] = age_result[0]
            features['domain_age_display'] = age_result[1]
        else:
            features['domain_age'] = age_result
            features['domain_age_display'] = "Не определен"
        
        return features
    
    def get_domain_age(self, domain):
        if not domain: 
            return (365, "Не определен")
        
        result = [None]
        
        def _get_age():
            try:
                age = self._get_domain_age_api(domain)
                if age and age != 3650 and age > 0:
                    result[0] = (age, self._format_age_display(age))
                    return
                
                age = self._get_domain_age_whois(domain)
                if age and age != 3650 and age > 0:
                    result[0] = (age, self._format_age_display(age))
                    return
                
                age = self._get_domain_age_system_whois(domain)
                if age and age != 3650 and age > 0:
                    result[0] = (age, self._format_age_display(age))
                    return
                
                age = self._get_domain_age_dns(domain)
                if age and age != 3650 and age > 0:
                    result[0] = (age, self._format_age_display(age))
                    return
                
                result[0] = (365, "Не определен")
            except Exception as e:
                result[0] = (365, "Не определен")
        
        thread = threading.Thread(target=_get_age)
        thread.daemon = True
        thread.start()
        thread.join(timeout=5.0)
        
        if thread.is_alive():
            return (365, "Не определен")
        
        if result[0] is not None:
            return result[0]
        
        return (365, "Не определен")
    
    def _format_age_display(self, age_days):
        return f"{age_days} дней"
    
    def _get_domain_age_system_whois(self, domain):
        try:
            import subprocess
            import platform
            
            if platform.system() == 'Windows':
                whois_cmd = 'whois'
            else:
                whois_cmd = 'whois'
            
            result = subprocess.run(
                [whois_cmd, domain],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0 and result.stdout:
                output = result.stdout
                
                date_patterns = [
                    r'Creation Date:\s*(\d{4}-\d{2}-\d{2})',
                    r'Created:\s*(\d{4}-\d{2}-\d{2})',
                    r'Created On:\s*(\d{4}-\d{2}-\d{2})',
                    r'Creation Date:\s*(\d{2}/\d{2}/\d{4})',
                    r'Created:\s*(\d{2}/\d{2}/\d{4})',
                    r'created:\s*(\d{4}-\d{2}-\d{2})',
                    r'Creation Date:\s*(\d{2}-\d{2}-\d{4})',
                    r'Registered:\s*(\d{4}-\d{2}-\d{2})',
                    r'Registration Date:\s*(\d{4}-\d{2}-\d{2})',
                ]
                
                for pattern in date_patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        date_str = match.group(1)
                        try:
                            from dateutil import parser
                            cd = parser.parse(date_str, fuzzy=True)
                            age_days = (datetime.now() - cd).days
                            if age_days >= 0:
                                return age_days
                        except Exception as e:
                            pass
                            
                        date_formats = ['%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y', '%Y/%m/%d']
                        for fmt in date_formats:
                            try:
                                cd = datetime.strptime(date_str, fmt)
                                age_days = (datetime.now() - cd).days
                                if age_days >= 0:
                                    return age_days
                            except ValueError:
                                continue
        
        except Exception as e:
            pass
        
        return None
    
    def _get_domain_age_whois(self, domain):
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(15)
        
        try:
            domain_info = whois.whois(domain)
            
            if domain_info is None:
                return None
            
            creation_date = None
            
            if isinstance(domain_info, dict):
                creation_date = (domain_info.get('creation_date') or 
                               domain_info.get('created') or 
                               domain_info.get('creation') or
                               domain_info.get('creation date'))
            else:
                for attr_name in ['creation_date', 'created', 'creation', 'creation_date_normalized']:
                    if hasattr(domain_info, attr_name):
                        attr_value = getattr(domain_info, attr_name)
                        if attr_value and attr_value not in [None, [], '']:
                            creation_date = attr_value
                            break
                
                if not creation_date and hasattr(domain_info, '__dict__'):
                    d = domain_info.__dict__
                    for key in ['creation_date', 'created', 'creation', 'creation date', 'creation_date_normalized']:
                        if key in d and d[key] not in [None, [], '']:
                            creation_date = d[key]
                            break
                
                if not creation_date and hasattr(domain_info, '__dict__'):
                    d = domain_info.__dict__
                    for key, value in d.items():
                        if ('date' in key.lower() or 'created' in key.lower()) and value:
                            if isinstance(value, (datetime, list)) or (isinstance(value, str) and len(value) > 5):
                                creation_date = value
                                break
            
            if creation_date:
                if isinstance(creation_date, list) and len(creation_date) > 0:
                    creation_date = creation_date[0]
                
                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                    if age_days >= 0:
                        return age_days
                    
                if creation_date:
                    date_str = str(creation_date).strip()
                    if date_str and date_str.lower() not in ['none', 'null', '', 'na', 'n/a']:
                        try:
                            from dateutil import parser
                            cd = parser.parse(date_str, fuzzy=True)
                            age_days = (datetime.now() - cd).days
                            if age_days >= 0:
                                return age_days
                        except (ImportError, ValueError, AttributeError, TypeError) as e:
                            pass
                        
                        try:
                            clean_str = date_str.replace('Z', '+00:00') if date_str.endswith('Z') else date_str
                            cd = datetime.fromisoformat(clean_str)
                            age_days = (datetime.now() - cd).days
                            if age_days >= 0:
                                return age_days
                        except (ValueError, AttributeError):
                            pass
                        
                        date_formats = [
                            '%Y-%m-%d %H:%M:%S',
                            '%Y-%m-%d',
                            '%d-%m-%Y',
                            '%d.%m.%Y',
                            '%Y/%m/%d',
                            '%d/%m/%Y',
                            '%Y-%m-%dT%H:%M:%S',
                            '%Y-%m-%dT%H:%M:%SZ',
                            '%Y-%m-%dT%H:%M:%S.%f',
                            '%Y-%m-%dT%H:%M:%S.%fZ',
                            '%Y-%m-%d %H:%M:%S.%f',
                            '%b %d %Y',
                            '%d %b %Y',
                            '%B %d, %Y',
                            '%d-%b-%Y',
                            '%Y.%m.%d',
                        ]
                        
                        for fmt in date_formats:
                            try:
                                cd = datetime.strptime(date_str, fmt)
                                age_days = (datetime.now() - cd).days
                                if age_days >= 0:
                                    return age_days
                            except (ValueError, AttributeError):
                                continue
                                
        except socket.timeout:
            pass
        except socket.gaierror as e:
            pass
        except Exception as e:
            pass
        finally:
            socket.setdefaulttimeout(old_timeout)
        
        return None
    
    def _get_domain_age_api(self, domain):
        try:
            api_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            params = {
                'domainName': domain,
                'outputFormat': 'JSON',
                'apiKey': os.getenv('WHOIS_API_KEY', '')
            }
            response = requests.get(api_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'WhoisRecord' in data:
                    record = data['WhoisRecord']
                    date_fields = ['createdDate', 'createdDateNormalized', 'registryData', 'created']
                    
                    for field in date_fields:
                        if field in record and record[field]:
                            date_str = record[field]
                            try:
                                from dateutil import parser
                                cd = parser.parse(str(date_str), fuzzy=True)
                                age_days = (datetime.now() - cd).days
                                if age_days >= 0:
                                    return age_days
                            except Exception as e:
                                continue
                    
                    if 'registryData' in record and isinstance(record['registryData'], dict):
                        reg_data = record['registryData']
                        if 'createdDate' in reg_data:
                            try:
                                from dateutil import parser
                                cd = parser.parse(str(reg_data['createdDate']), fuzzy=True)
                                age_days = (datetime.now() - cd).days
                                if age_days >= 0:
                                    return age_days
                            except:
                                pass
        except Exception as e:
            pass
        
        try:
            api_url = f"https://ipwhois.app/json/{domain}"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'success' in data and data.get('success') and 'created' in data:
                    date_str = data['created']
                    try:
                        from dateutil import parser
                        cd = parser.parse(str(date_str), fuzzy=True)
                        age_days = (datetime.now() - cd).days
                        if age_days >= 0:
                            return age_days
                    except Exception as e:
                        pass
        except Exception as e:
            pass
        
        try:
            api_url = f"https://www.whois.com/whois/{domain}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.content, 'html.parser')
                text = soup.get_text()
                date_patterns = [
                    r'Creation Date:\s*(\d{4}-\d{2}-\d{2})',
                    r'Created:\s*(\d{4}-\d{2}-\d{2})',
                    r'Created On:\s*(\d{4}-\d{2}-\d{2})',
                    r'Registration Date:\s*(\d{4}-\d{2}-\d{2})',
                    r'Registered:\s*(\d{4}-\d{2}-\d{2})',
                ]
                
                for pattern in date_patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        date_str = match.group(1)
                        try:
                            from dateutil import parser
                            cd = parser.parse(date_str, fuzzy=True)
                            age_days = (datetime.now() - cd).days
                            if age_days >= 0:
                                return age_days
                        except:
                            continue
        except Exception as e:
            pass
        
        try:
            api_url = f"https://api.domain.com/v1/whois/{domain}"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'created_date' in data or 'creation_date' in data:
                    date_str = data.get('created_date') or data.get('creation_date')
                    try:
                        from dateutil import parser
                        cd = parser.parse(str(date_str), fuzzy=True)
                        age_days = (datetime.now() - cd).days
                        if age_days >= 0:
                            return age_days
                    except:
                        pass
        except:
            pass
        
        return None
    
    def _get_domain_age_dns(self, domain):
        try:
            import dns.resolver
            import dns.exception
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            try:
                answers = resolver.resolve(domain, 'SOA')
                if answers:
                    soa = answers[0]
                    serial = soa.serial
                    
                    if serial > 10000000:
                        serial_str = str(serial)
                        if len(serial_str) >= 8:
                            year = int(serial_str[:4])
                            month = int(serial_str[4:6])
                            day = int(serial_str[6:8])
                            try:
                                cd = datetime(year, month, day)
                                age_days = (datetime.now() - cd).days
                                if age_days >= 0 and age_days < 36500:
                                    return age_days
                            except:
                                pass
            except (dns.exception.DNSException, Exception):
                pass
        except ImportError:
            pass
        except:
            pass
        return None
    
    def analyze_html_content(self, url):
        features = {'has_password_field': 0, 'form_action_external': 0, 'phishing_keywords': 0}
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')
            
            forms = soup.find_all('form')
            
            if forms:
                password_fields = soup.find_all('input', {'type': 'password'})
                features['has_password_field'] = 1 if password_fields else 0
                
                for form in forms:
                    action = form.get('action', '')
                    if action and not action.startswith(('#', '/')) and url not in action:
                        features['form_action_external'] = 1
                        break
            
            text = soup.get_text().lower()
            keywords = ['login', 'password', 'verify', 'account', 'secure', 'banking', 'update', 'confirm']
            features['phishing_keywords'] = sum(1 for k in keywords if k in text)
            
        except:
            pass
        return features
    
    def check_whitelist(self, url):
        try:
            domain = tldextract.extract(url).registered_domain.lower()
            return domain in self.whitelist
        except: return False
    
    def check_blacklist(self, url):
        try:
            domain = tldextract.extract(url).registered_domain.lower()
            if domain in self.known_phishing_domains:
                return True
            for d in self.known_phishing_domains:
                if domain.endswith("." + d):
                    return True
            return False
        except:
            return False

    def load_or_train_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except:
                self.train_model()
        else:
            self.train_model()
    
    def train_model(self, dataset_path='phishing_dataset.csv'):
        self.model = None

    def predict_phishing(self, url):
        
        if not url.startswith(('http://', 'https://')):
            target_url = 'https://' + url
        else:
            target_url = url

        try:
            extracted = tldextract.extract(target_url)
            is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", extracted.domain)
            
            if not extracted.suffix and not is_ip and extracted.domain != 'localhost':
                return {'error': 'Некорректный URL. Введите адрес сайта (например, google.com)'}
                
        except Exception as e:
            return {'error': 'Ошибка проверки формата URL'}

        url = target_url 

        if self.check_blacklist(url):
            return {
                'url': url, 'is_phishing': True, 'confidence': 1.0, 
                'risk_level': 'CRITICAL', 'reason': 'Blacklist', 
                'special_message': 'URL находится в базе небезопасных доменов, ни в коем случае не переходите по ней!'
            }
        
        if self.check_whitelist(url):
            domain_info = tldextract.extract(url)
            registered_domain = domain_info.registered_domain.lower()
            all_safe_domains = set(self.whitelist)
            is_safe_domain = registered_domain in all_safe_domains
            
            return {
                'url': url, 'is_phishing': False, 'confidence': 0.0, 
                'risk_level': 'SAFE', 'reason': 'Whitelist', 'is_safe_domain': is_safe_domain,
                'special_message': 'URL находится в базе полностью безопасных доменов, дополнительная проверка не требуется'
            }

        try:
            vt_stats = self.check_virustotal(url)
            vt_malicious = vt_stats.get('malicious', 0)
            vt_suspicious = vt_stats.get('suspicious', 0)
            
            if vt_malicious >= 1 or vt_suspicious >= 2:
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
            vt_stats = {}

        try:
            domain_info = tldextract.extract(url)
            registered_domain = domain_info.registered_domain.lower()
            all_safe_domains = set(self.whitelist)
            is_safe_domain = registered_domain in all_safe_domains
            
            url_features = self.extract_url_features(url)
            html_features = self.analyze_html_content(url)
            all_features = {**url_features, **html_features}
            
            if all_features.get('is_typosquatting', 0) == 1:
                domain_info = tldextract.extract(url)
                registered_domain = domain_info.registered_domain.lower()
                all_safe_domains = set(self.whitelist)
                is_safe_domain = registered_domain in all_safe_domains
                
                return {
                    'url': url,
                    'is_phishing': True,
                    'confidence': 1.0,
                    'risk_level': 'CRITICAL',
                    'reason': 'Typosquatting Detected',
                    'features': all_features,
                    'vt_stats': vt_stats,
                    'is_safe_domain': is_safe_domain
                }
            
            feature_names = [
                'url_length', 'has_ip', 'at_symbol', 'double_slash', 'is_shortened',
                'subdomain_count', 'domain_length', 'digit_ratio',
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
            
            if all_features.get('domain_age', 0) > 365:
                confidence = min(confidence, 0.4)
                if confidence < 0.5: is_phishing = False

            domain_age = all_features.get('domain_age', 365)
            domain_age_display = all_features.get('domain_age_display', 'Не определен')
            young_domain_risk = False
            
            if domain_age < 30:
                young_domain_risk = True
            elif domain_age == 365 and domain_age_display == "Не определен":
                young_domain_risk = True

            risk = "LOW"
            if confidence > 0.8: risk = "CRITICAL"
            elif confidence > 0.6: risk = "HIGH"
            elif confidence > 0.4: risk = "MEDIUM"

            return {
                'url': url,
                'is_phishing': bool(is_phishing),
                'confidence': float(confidence),
                'risk_level': risk,
                'features': all_features,
                'vt_stats': vt_stats,
                'is_safe_domain': is_safe_domain,
                'young_domain_risk': young_domain_risk
            }
            
        except Exception as e:
            try:
                domain_info = tldextract.extract(url)
                registered_domain = domain_info.registered_domain.lower()
                all_safe_domains = set(self.whitelist)
                is_safe_domain = registered_domain in all_safe_domains
            except:
                is_safe_domain = False
            return {'url': url, 'error': str(e), 'is_phishing': False, 'risk_level': 'UNKNOWN', 'confidence': 0, 'is_safe_domain': is_safe_domain}
