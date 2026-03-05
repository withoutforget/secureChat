# secureChat

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

p.s. Сейчас тут нет ed25519, потому что, по сути, он работает независимо от этой схемы.
При самой передаче сообщения с солью и публчиным ключом надо его отправлять.

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