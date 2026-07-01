//go:build linux
// +build linux

package keyring

import (
	"strings"

	"github.com/godbus/dbus"
)

const (
	secretServiceDBusName = "org.freedesktop.secrets"
	secretServiceDBusPath = "/org/freedesktop/secrets"
)

type secretDBusObject interface {
	Path() dbus.ObjectPath
}

type secretService struct {
	conn      *dbus.Conn
	dbus      dbus.BusObject
	closeFunc func() error
}

func newSecretService() (*secretService, error) {
	conn, err := newPrivateSessionBus()
	if err != nil {
		return nil, err
	}

	return &secretService{
		conn:      conn,
		dbus:      conn.Object(secretServiceDBusName, secretServiceDBusPath),
		closeFunc: conn.Close,
	}, nil
}

func (service *secretService) Close() error {
	if service == nil {
		return nil
	}
	if service.closeFunc != nil {
		return service.closeFunc()
	}
	if service.conn == nil {
		return nil
	}
	return service.conn.Close()
}

func (service secretService) Path() dbus.ObjectPath {
	return service.dbus.Path()
}

func (service *secretService) Open() (*secretSession, error) {
	var output dbus.Variant
	var path dbus.ObjectPath

	err := service.dbus.Call("org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &path)
	if err != nil {
		return nil, err
	}

	return newSecretSession(service.conn, path), nil
}

func (service *secretService) Collections() ([]secretCollection, error) {
	val, err := service.dbus.GetProperty("org.freedesktop.Secret.Service.Collections")
	if err != nil {
		return nil, err
	}

	collections := []secretCollection{}
	for _, path := range val.Value().([]dbus.ObjectPath) {
		collections = append(collections, *newSecretCollection(service.conn, path))
	}
	return collections, nil
}

func (service *secretService) CreateCollection(label string) (*secretCollection, error) {
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant(label),
	}

	var path dbus.ObjectPath
	var prompt dbus.ObjectPath

	err := service.dbus.Call("org.freedesktop.Secret.Service.CreateCollection", 0, properties, "").Store(&path, &prompt)
	if err != nil {
		return nil, err
	}

	if isSecretPrompt(prompt) {
		result, err := newSecretPrompt(service.conn, prompt).Prompt()
		if err != nil {
			return nil, err
		}
		path = result.Value().(dbus.ObjectPath)
	}

	return newSecretCollection(service.conn, path), nil
}

func (service *secretService) Unlock(object secretDBusObject) error {
	objects := []dbus.ObjectPath{object.Path()}

	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath

	err := service.dbus.Call("org.freedesktop.Secret.Service.Unlock", 0, objects).Store(&unlocked, &prompt)
	if err != nil {
		return err
	}

	if isSecretPrompt(prompt) {
		_, err := newSecretPrompt(service.conn, prompt).Prompt()
		return err
	}
	return nil
}

type secretSession struct {
	conn *dbus.Conn
	dbus dbus.BusObject
}

func newSecretSession(conn *dbus.Conn, path dbus.ObjectPath) *secretSession {
	return &secretSession{
		conn: conn,
		dbus: conn.Object(secretServiceDBusName, path),
	}
}

func (session secretSession) Path() dbus.ObjectPath {
	return session.dbus.Path()
}

type secretCollection struct {
	conn *dbus.Conn
	dbus dbus.BusObject
}

func newSecretCollection(conn *dbus.Conn, path dbus.ObjectPath) *secretCollection {
	return &secretCollection{
		conn: conn,
		dbus: conn.Object(secretServiceDBusName, path),
	}
}

func (collection secretCollection) Path() dbus.ObjectPath {
	return collection.dbus.Path()
}

func (collection *secretCollection) Items() ([]secretItem, error) {
	val, err := collection.dbus.GetProperty("org.freedesktop.Secret.Collection.Items")
	if err != nil {
		return nil, err
	}

	items := []secretItem{}
	for _, path := range val.Value().([]dbus.ObjectPath) {
		items = append(items, *newSecretItem(collection.conn, path))
	}
	return items, nil
}

func (collection *secretCollection) Delete() error {
	var prompt dbus.ObjectPath

	err := collection.dbus.Call("org.freedesktop.Secret.Collection.Delete", 0).Store(&prompt)
	if err != nil {
		return err
	}

	if isSecretPrompt(prompt) {
		_, err := newSecretPrompt(collection.conn, prompt).Prompt()
		return err
	}
	return nil
}

func (collection *secretCollection) SearchItems(profile string) ([]secretItem, error) {
	attributes := map[string]string{"profile": profile}

	var paths []dbus.ObjectPath
	err := collection.dbus.Call("org.freedesktop.Secret.Collection.SearchItems", 0, attributes).Store(&paths)
	if err != nil {
		return nil, err
	}

	items := []secretItem{}
	for _, path := range paths {
		items = append(items, *newSecretItem(collection.conn, path))
	}
	return items, nil
}

func (collection *secretCollection) CreateItem(label string, secret *secretPayload, replace bool) (*secretItem, error) {
	attributes := map[string]string{"profile": label}
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Item.Label":      dbus.MakeVariant(label),
		"org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(attributes),
	}

	var path dbus.ObjectPath
	var prompt dbus.ObjectPath

	err := collection.dbus.Call("org.freedesktop.Secret.Collection.CreateItem", 0, properties, secret, replace).Store(&path, &prompt)
	if err != nil {
		return nil, err
	}

	if isSecretPrompt(prompt) {
		result, err := newSecretPrompt(collection.conn, prompt).Prompt()
		if err != nil {
			return nil, err
		}
		path = result.Value().(dbus.ObjectPath)
	}

	return newSecretItem(collection.conn, path), nil
}

func (collection *secretCollection) Locked() (bool, error) {
	val, err := collection.dbus.GetProperty("org.freedesktop.Secret.Collection.Locked")
	if err != nil {
		return true, err
	}
	return val.Value().(bool), nil
}

type secretItem struct {
	conn *dbus.Conn
	dbus dbus.BusObject
}

func newSecretItem(conn *dbus.Conn, path dbus.ObjectPath) *secretItem {
	return &secretItem{
		conn: conn,
		dbus: conn.Object(secretServiceDBusName, path),
	}
}

func (item secretItem) Path() dbus.ObjectPath {
	return item.dbus.Path()
}

func (item *secretItem) Label() (string, error) {
	val, err := item.dbus.GetProperty("org.freedesktop.Secret.Item.Label")
	if err != nil {
		return "", err
	}
	return val.Value().(string), nil
}

func (item *secretItem) Locked() (bool, error) {
	val, err := item.dbus.GetProperty("org.freedesktop.Secret.Item.Locked")
	if err != nil {
		return true, err
	}
	return val.Value().(bool), nil
}

func (item *secretItem) GetSecret(session *secretSession) (*secretPayload, error) {
	secret := secretPayload{}

	err := item.dbus.Call("org.freedesktop.Secret.Item.GetSecret", 0, session.Path()).Store(&secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func (item *secretItem) Delete() error {
	var prompt dbus.ObjectPath

	err := item.dbus.Call("org.freedesktop.Secret.Item.Delete", 0).Store(&prompt)
	if err != nil {
		return err
	}

	if isSecretPrompt(prompt) {
		_, err := newSecretPrompt(item.conn, prompt).Prompt()
		return err
	}
	return nil
}

type secretPrompt struct {
	conn *dbus.Conn
	dbus dbus.BusObject
}

func newSecretPrompt(conn *dbus.Conn, path dbus.ObjectPath) *secretPrompt {
	return &secretPrompt{
		conn: conn,
		dbus: conn.Object(secretServiceDBusName, path),
	}
}

func (prompt secretPrompt) Path() dbus.ObjectPath {
	return prompt.dbus.Path()
}

func isSecretPrompt(path dbus.ObjectPath) bool {
	return strings.HasPrefix(string(path), secretServiceDBusPath+"/prompt/")
}

func (prompt *secretPrompt) Prompt() (*dbus.Variant, error) {
	c := make(chan *dbus.Signal, 10)
	defer close(c)

	prompt.conn.Signal(c)
	defer prompt.conn.RemoveSignal(c)

	err := prompt.dbus.Call("org.freedesktop.Secret.Prompt.Prompt", 0, "").Store()
	if err != nil {
		return nil, err
	}

	for {
		if result := <-c; result.Path == prompt.Path() {
			value := result.Body[1].(dbus.Variant)
			return &value, nil
		}
	}
}

type secretPayload struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func newSecret(session *secretSession, params []byte, value []byte, contentType string) *secretPayload {
	return &secretPayload{
		Session:     session.Path(),
		Parameters:  params,
		Value:       value,
		ContentType: contentType,
	}
}
