# secureChat
<div align="center">

![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-20.10+-2496ED?logo=docker&logoColor=white)
![Docker Compose](https://img.shields.io/badge/Docker_Compose-v2-2496ED?logo=docker&logoColor=white)
![just](https://img.shields.io/badge/just-task_runner-EFF1F3?logo=just&logoColor=black)
![golangci-lint](https://img.shields.io/badge/golangci--lint-v2-yellow)
![Git](https://img.shields.io/badge/Git-any-F05032?logo=git&logoColor=white)

</div>

---

Простенький секурный клиент для безопасного обмена сообщениями. Использует надёжное шифрование.

Сервер может быть любым — это не более, чем прослойка для обмена сообщениями. В теории, даже если он будет скомпроментирован, то получить доступ к переписке невозможно*.

*Единственный нюанс: необходимо безопасно обменяться ed25519 ключами. В таком случае MITM действительно будет невозможно. В иных случаях, если сервер скомпроментирован, либо трафик к сайту может быть подменён третьей стороной любым образом, нельзя гарантировать отсутствие MITM.

## Установка
```sh
git clone git@github.com:withoutforget/secureChat.git
cd ./secureChat/
just server # запускает сервер
just client # запускает клиент
```


## Example

p.s. В примере нет ed25519, потому что, по сути, он работает независимо от этой схемы.
При самой передаче сообщения с солью и публчиным ключом надо его отправлять. В фактической реализации он присутствует.

```go
func main() {
	// Создаём клиента 1
	client1, err := message.NewSecretMessage()
	if err != nil {
		panic(err)
	}
	// Создаём клиента 2
	client2, err := message.NewSecretMessage()
	if err != nil {
		panic(err)
	}

	// обмениваемся солью и публичными ключами
	c1Salt, c2Salt := client1.GetSalt(), client2.GetSalt()
	key1, key2 := client1.GetPublicKey(), client2.GetPublicKey()
	
	// у каждого клиента устанавливаем общий ключ
	// также тут происходит генерация aes-gcm
	err = client1.SetUpSharedKey(key2, c2Salt)
	if err != nil {
		panic(err)
	}
	err = client2.SetUpSharedKey(key1, c1Salt)
	if err != nil {
		panic(err)
	}

	// шифрование сообщения
	enc, err := client1.GenerateMessage([]byte("Hello world from me!"))
	if err != nil {
		panic(err)
	}
	// расшифровка сообщения
	dec, err := client2.ReadMessage(enc)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(dec))
}
```

## Описание алгоритма.

Заранее скажу, что ed25519 не является обязательным и его можно пропустить. Тогда просто будет уведомление.

1. Два человека заранее договариваются о ed25519 и обмениваются публичными ключами. Это необходимо, чтобы при handshake верифицировать подлинность собеседника. Исключает атаку MITM, даже если вся сеть, сервер скомпроментированы.
2. Клиент А отправляет на сервер свой публичный ключ X25519 и сгенерированную соль, при этом подписывая их через ed25519. Если подпись невалидна, то клиент Б увидит предупреждение об этом.
3. В свою очередь клиент Б отправляет также публичный ключ и соль, подписанные через ed25519. 
4. Оба клиента вычисляют общий [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) ключ, а также с помощью XOR генерируют общую соль.
5. На основе ECDH и соли каждый клиент генерирует writeKey и readKey. Это AES-GCM ключи.
6. Клиент А шифрует сообщение и отправляет клиенту Б. Success!