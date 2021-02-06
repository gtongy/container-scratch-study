// +build linux

package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	digest = randomHash()
)

type Unsetter func() error

func SetupBridge(name string) error {
	bridge, err := netlink.LinkByName(name)
	if err != nil {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = name
		bridge = &netlink.Bridge{
			LinkAttrs: linkAttrs,
		}
		if err := netlink.LinkAdd(bridge); err != nil {
			return err
		}
	}
	addrList, err := netlink.AddrList(bridge, 0)
	if err != nil {
		return err
	}
	if len(addrList) < 1 {
		IP := "172.30.0.1/16"
		addr, err := netlink.ParseAddr(IP)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(bridge, addr); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetUp(bridge); err != nil {
		return err
	}
	return nil
}

func SetupNetwork(bridge string) (error, error){
	nsMountTarget := filepath.Join("/gtongy/netns", digest)
	vethName := fmt.Sprintf("veth%.7s", digest)
	peerName := fmt.Sprintf("P%s", vethName)
	if err := SetupVirtualEthernet(vethName, peerName); err != nil {
		return nil, err
	}
	if err := LinkSetMaster(vethName, bridge); err != nil {
		return nil, err
	}
	unmount, err := MountNetworkNamespace(nsMountTarget)
	if err != nil {
		return unmount, err
	}
	if err := LinkSetNsByFile(nsMountTarget, peerName); err != nil {
		return unmount, nil
	}
	// Change current network namespace to setup the veth
	unset, err := SetNetNSByFile(nsMountTarget)
	if err != nil {
		return unmount, err
	}
	defer unset()

	ctrEthName := "gtongy0"
	ctrEthIPAddr := GetIP()
	if err := LinkRename(peerName, ctrEthName); err != nil {
		return unmount, err
	}
	if err := LinkAddAddr(ctrEthName, ctrEthIPAddr); err != nil {
		return unmount, err
	}
	if err := LinkSetup(ctrEthName); err != nil {
		return unmount, err
	}
	if err := LinkAddGateway(ctrEthName, "172.30.0.1"); err != nil {
		return unmount, err
	}
	if err := LinkSetup("lo"); err != nil {
		return unmount, err
	}
	return unmount, nil
}

func SetupVirtualEthernet(name, peer string) error {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = name
	vth := &netlink.Veth{
		LinkAttrs: linkAttrs,
		PeerName:  peer,
	}
	if err := netlink.LinkAdd(vth); err != nil {
		return err
	}
	return netlink.LinkSetUp(vth)
}

// LinkSetMaster setup bridge and veth
func LinkSetMaster(linkName, masterName string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return errors.Wrapf(err, "can not find link %s", linkName)
	}
	masterLink, err := netlink.LinkByName(masterName)
	if err != nil {
		return errors.Wrapf(err, "can not find link %s", masterName)
	}
	if err := netlink.LinkSetMaster(link, masterLink); err != nil {
		return err
	}
	return nil
}

// MountNetworkNamespace mount network to last lifetime.
func MountNetworkNamespace(nsTarget string) (error, error) {
	_, err := os.OpenFile(nsTarget, syscall.O_RDONLY|syscall.O_CREAT|syscall.O_EXCL, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create target file")
	}
	file, err := os.OpenFile("/proc/self/ns/net", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		return nil, errors.Wrap(err, "unshare syscall failed")
	}
	// TODO: mount file
	if err := unix.Setns(int(file.Fd()), syscall.CLONE_NEWNET); err != nil {
		// TODO: return unmount
		return nil, error.Wrap(err, "setns syscall failed")
	}
	// TODO: return unmount
	return nil, err
}

func LinkSetNsByFile(filename, linkName string) error {
	netnsFile, err := os.OpenFile(filename, syscall.O_RDONLY, 0)
	if err != nil {
		return errors.Wrap(err, "unable to open netns file")
	}
	defer netnsFile.Close()
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}
	// puts the device into a new network namespace
	return netlink.LinkSetNsFd(link, int(netnsFile.Fd()))
}

func SetNetNSByFile(filename string) (Unsetter, error) {
	currentNS, err := os.OpenFile("/proc/self/ns/net", os.O_RDONLY, 0)
	unsetFunc := func() error {
		defer currentNS.Close()
		if err != nil {
			return err
		}
		return unix.Setns(int(currentNS.Fd()), syscall.CLONE_NEWNET)
	}
	netnsFile, err := os.OpenFile(filename, syscall.O_RDONLY, 0)
	if err != nil {
		return unsetFunc, errors.Wrap(err, "unable to open network namespace file")
	}
	defer netnsFile.Close()
	if err := unix.Setns(int(netnsFile.Fd()), syscall.CLONE_NEWNET); err != nil {
		return unsetFunc, errors.Wrap(err, "unset syscall failed")
	}
	return unsetFunc, err
}

func GetIP() string {
	a, _ := strconv.ParseInt(digest[:2], 10, 64)
	b, _ := strconv.ParseInt(digest[62:], 10, 64)
	return fmt.Sprintf("172.30.%d.%d/16", a, b)
}

func LinkRename(old, new string) error {
	link, err := netlink.LinkByName(old)
	if err != nil {
		return err
	}
	return netlink.LinkSetName(link, new)
}

func LinkAddAddr(linkName, IP string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(IP)
	if err != nil {
		return errors.Wrapf(err, "can not parse %s", IP)
	}
	return netlink.AddrAdd(link, addr)
}

func LinkSetup(linkName string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func LinkAddGateway(linkName, gatewayIP string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}
	newRoute := &netlink.Route{
		LinkIndex:  link.Attrs().Index,
		Scope:      netlink.SCOPE_UNIVERSE,
		Gw:         net.ParseIP(gatewayIP),
	}
	return netlink.RouteAdd(newRoute)
}


func randomHash() string {
	randBuffer := make([]byte, 32)
	rand.Read(randBuffer)
	sha := sha256.New().Sum(randBuffer)
	return fmt.Sprintf("%x", sha)[:64]
}
