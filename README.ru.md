<div align="center">

# 📧 Yggmail

End-to-end шифрованная почта через сеть Yggdrasil с поддержкой Android

[![Лицензия](https://img.shields.io/github/license/JB-SelfCompany/yggmail)](LICENSE)
![Go](https://img.shields.io/badge/go-1.25+-00ADD8.svg)
[![Посетители](https://visitor-badge.laobi.icu/badge?page_id=JB-SelfCompany.yggmail)](https://github.com/JB-SelfCompany/yggmail)

**[English](README.md) | [Русский](#)**

</div>

---

> **Примечание**: Это форк [оригинального проекта Yggmail](https://github.com/neilalexander/yggmail) с добавленной поддержкой компиляции Android-библиотеки через gomobile.

## ✨ Возможности

- 📬 Почтовый ящик хранится на вашем устройстве
- 🔐 Весь почтовый трафик зашифрован end-to-end через Yggdrasil
- 📱 IMAP/SMTP протоколы для стандартных почтовых клиентов
- 🌐 Автоматическое обнаружение пиров через multicast
- 📲 Поддержка Android-библиотеки через gomobile

---

## 📦 Установка

### Требования

- Go 1.25.5 или новее
- CGO включён (требуется для SQLite)
- C-компилятор (gcc на Linux/macOS, MinGW на Windows)

### Установка

```bash
go install github.com/JB-SelfCompany/yggmail/cmd/yggmail@latest
```

### Сборка из исходников

```bash
git clone https://github.com/JB-SelfCompany/yggmail.git
cd yggmail
go build -o yggmail ./cmd/yggmail
```

### Docker

```bash
docker build -t yggmail .
docker run -p 1025:1025 -p 1143:1143 -v /path/to/data:/etc/yggmail yggmail -multicast
```

---

## 🚀 Быстрый старт

```bash
# Установка пароля (создаёт БД)
yggmail -password

# Запуск с multicast-обнаружением
yggmail -multicast

# Или со статическим пиром
yggmail -peer=tls://[peer-address]:port
```

Подключите почтовый клиент:
- **SMTP**: localhost:1025 (без SSL)
- **IMAP**: localhost:1143 (без SSL)

---

## ⚙️ Параметры

| Флаг | Описание |
|------|----------|
| `-peer=tls://...` | Подключиться к пиру Yggdrasil |
| `-multicast` | Включить обнаружение пиров в LAN |
| `-database=/path/to/yggmail.db` | Путь к файлу БД |
| `-smtp=addr:port` | Адрес прослушивания SMTP |
| `-imap=addr:port` | Адрес прослушивания IMAP |
| `-password` | Установить пароль IMAP/SMTP |

---

## 📱 Android-библиотека

### Сборка AAR

```bash
# Установка gomobile
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# Сборка (с обходом для Go 1.24+)
cd mobile
gomobile bind -target=android -androidapi 23 -ldflags="-checklinkname=0" -o yggmail.aar github.com/JB-SelfCompany/yggmail/mobile
```

### Использование в Android

```kotlin
import mobile.Mobile
import mobile.YggmailService

val service = Mobile.newYggmailService(dbPath, "localhost:1025", "localhost:1143")
service.initialize()
service.start("tls://peer:port", true, ".*")

val address = service.mailAddress
```

---

## 🔧 Добавления в форке

- **Mobile bindings** (`mobile/yggmail.go`): Полный API для Android/iOS
- **Поддержка больших файлов**: Сообщения >1MB хранятся в файловой системе (до 500MB)
- **Лимиты размера**: Настраиваемый максимальный размер сообщения
- **Оптимизация батареи**: Адаптивные таймеры для мобильных
- **Переключение сетей**: Обработка WiFi ↔ Mobile

---

## 📝 Примечания

- Yggmail должен работать для получения писем
- Адрес `From` должен совпадать с вашим адресом Yggmail
- Только доставка Yggmail-to-Yggmail (не Интернет-почта)
- Поддерживаются домены `@yggmail` и `@yggmail.local`

---

## 📄 Лицензия

GNU General Public License v3.0 - см. [LICENSE](LICENSE)

---

<div align="center">

Made with ❤️ by <a href="https://github.com/JB-SelfCompany">JB-SelfCompany</a>

</div>
