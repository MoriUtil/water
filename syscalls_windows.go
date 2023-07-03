package water

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

type wintun struct {
	dev tun.Device
}

func (w *wintun) Close() error {
	return w.dev.Close()
}

func (w *wintun) Write(b []byte) (int, error) {
	return w.dev.Write(b, 0)
}

func (w *wintun) Read(b []byte) (int, error) {
	return w.dev.Read(b, 0)
}

func openDev(config Config) (ifce *Interface, err error) {
	if config.DeviceType == TAP {
		return nil, err
	}

	guid, err := windows.GUIDFromString("{53fdcb66-d364-2fde-ee1c-ea0ba9a58cbd}")
	if err != nil {
		panic(err)
	}

	tun.WintunTunnelType = "Atom"
	dev, err := tun.CreateTUNWithRequestedGUID(config.PlatformSpecificParams.Name, &guid, 0)
	if err != nil {
		return nil, err
	}
	wintun := &wintun{dev: dev}
	ifce = &Interface{isTAP: false, ReadWriteCloser: wintun, name: config.PlatformSpecificParams.Name}
	return ifce, nil
}
