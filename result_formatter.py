def format_result_for_display(result):
    formatted = result.copy()
    
    risk_translations = {
        'SAFE': 'БЕЗОПАСНЫЙ',
        'LOW': 'НИЗКИЙ',
        'MEDIUM': 'СРЕДНИЙ',
        'HIGH': 'ВЫСОКИЙ',
        'CRITICAL': 'КРИТИЧЕСКИЙ',
        'UNKNOWN': 'НЕИЗВЕСТНЫЙ'
    }
    
    formatted['risk_level_ru'] = risk_translations.get(
        result.get('risk_level', 'UNKNOWN'), 
        result.get('risk_level', 'UNKNOWN')
    )
    
    confidence_percent = round(result.get('confidence', 0) * 100, 1)
    formatted['confidence_percent'] = confidence_percent
    
    if result.get('is_phishing'):
        formatted['verdict_text'] = 'Обнаружена угроза'
        formatted['verdict_description'] = 'Ссылка не является безопасной, крайне не рекомендуется переходить по ней.'
    else:
        formatted['verdict_text'] = 'Угроз не обнаружено'
        formatted['verdict_description'] = 'Ссылка является безопасной.'
    
    if result.get('special_message'):
        formatted['main_message'] = result['special_message']
    else:
        formatted['main_message'] = formatted['verdict_description']
    
    return formatted


def format_result_for_telegram(result):
    formatted = format_result_for_display(result)
    
    feature_translations = {
        'url_length': 'Длина URL',
        'has_ip': 'IP вместо домена',
        'at_symbol': 'Символ @ в URL',
        'double_slash': 'Двойной слэш //',
        'is_shortened': 'Сокращенная ссылка',
        'subdomain_count': 'Количество поддоменов',
        'domain_length': 'Длина домена',
        'digit_ratio': 'Доля цифр в домене',
        'brand_in_domain': 'Упоминание стороннего бренда',
        'has_https': 'HTTPS шифрование',
        'domain_age': 'Возраст домена',
        'domain_age_display': 'Возраст домена',
        'is_typosquatting': 'Тайпосквоттинг',
        'phishing_keywords': 'Фишинговые слова',
        'form_action_external': 'Внешние формы',
        'has_password_field': 'Поле для пароля'
    }
    
    message_parts = []
    
    message_parts.append(f"<b>Результаты анализа</b>")
    message_parts.append(f"<code>{result['url']}</code>\n")
    
    if formatted['is_phishing']:
        message_parts.append(f"<b>⚠️ Обнаружена угроза</b>\n")
    else:
        message_parts.append(f"<b>✅ Угроз не обнаружено</b>\n")
    
    if formatted.get('special_message'):
        message_parts.append(f"{formatted['special_message']}\n")
    else:
        message_parts.append(f"{formatted['verdict_description']}\n")
    
    if result.get('features'):
        message_parts.append(f"<b>Детали анализа:</b>")
        
        features = result['features']
        
        important_features = [
            'domain_age_display', 'domain_age',
            'has_https', 'has_ip', 'is_typosquatting',
            'brand_in_domain', 'is_shortened', 'subdomain_count'
        ]
        
        for key in important_features:
            if key in features:
                if key == 'domain_age_display':
                    continue
                elif key == 'domain_age':
                    display_key = feature_translations.get('domain_age', key)
                    age_display = features.get('domain_age_display', features.get('domain_age', 'Неизвестно'))
                    
                    if result.get('young_domain_risk', False):
                        value = f"{age_display} ⚠️ (фактор риска: возраст менее 30 дней или не определен)"
                    else:
                        value = age_display
                    message_parts.append(f"• {display_key}: {value}")
                elif key == 'has_https':
                    display_key = feature_translations.get(key, key)
                    value = "Да 🟢" if features[key] == 1 else "Нет 🔴"
                    message_parts.append(f"• {display_key}: {value}")
                elif key in ['has_ip', 'is_typosquatting', 'brand_in_domain', 'is_shortened']:
                    display_key = feature_translations.get(key, key)
                    value = "Да 🔴" if features[key] == 1 else "Нет 🟢"
                    message_parts.append(f"• {display_key}: {value}")
                else:
                    display_key = feature_translations.get(key, key)
                    message_parts.append(f"• {display_key}: {features[key]}")
    
    if result.get('vt_stats'):
        vt_stats = result['vt_stats']
        malicious = vt_stats.get('malicious', 0)
        suspicious = vt_stats.get('suspicious', 0)
        harmless = vt_stats.get('harmless', 0)
        
        if malicious > 0 or suspicious > 0:
            message_parts.append(f"\n<b>VirusTotal:</b>")
            message_parts.append(f"⚠️ Вредоносных: {malicious}")
            message_parts.append(f"⚠️ Подозрительных: {suspicious}")
            if harmless > 0:
                message_parts.append(f"✅ Безопасных: {harmless}")
    
    return "\n".join(message_parts)
