# 🛡️ ThreatLens

ThreatLens — это веб-приложение на Django для анализа файлов и URL с использованием:
- [VirusTotal API](https://www.virustotal.com/)
- [YARA](https://virustotal.github.io/yara/) (правила детекции угроз)
- SHA256-хеширования
- Поддержки истории сканирований, поиска и фильтрации

---

## 🚀 Возможности

- 📁 Загрузка файлов и URL-адресов для проверки
- 🔐 Генерация SHA256-хеша
- ☁️ Интеграция с VirusTotal (результаты по 70+ антивирусным движкам)
- 🔍 Проверка по YARA-правилам (встроенные или свои)
- 🧠 Отображение статистики: зловредов, ошибок YARA и дат
- 🔎 Поиск по SHA256 или URL
- ♻️ Очистка истории сканирований

---

## 🛠️ Установка

### 1. Клонирование и переход

```bash
   git clone https://github.com/your-username/threatlens.git
   cd threatlens
```

## 📂 Структура
```commandline
   threatlens/
│
├── scanner/               # Приложение анализа
│   ├── views.py           # Обработка логики
│   ├── models.py          # Модель Submission
│   ├── forms.py           # Форма загрузки
│   ├── urls.py            # URL-маршруты
│   ├── templates/
│   │   └── scanner/
│   │       ├── submit.html
│   │       └── results.html
│   ├── templatetags/
│   │   └── custom_filters.py  # Фильтр для typeof
│
├── rules/
│   └── rules.yar          # YARA-правила (включая EICAR)
│
├── db.sqlite3
└── manage.py

```

## 🧪 Примеры
* Пример YARA-правила (yara_rules/index.yar)

```commandline
   rule EICAR_Test_File {
    meta:
        description = "Detects the EICAR test file"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
```

## 🔐 VirusTotal API
* Зарегистрируйся на virustotal.com
* Получи API-ключ в настройках аккаунта
* Вставь его в .env или settings.py как VT_API_KEY




