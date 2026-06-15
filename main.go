package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type pktMsg struct {
	packet gopacket.Packet
}

type model struct {
	packets []string
	sub		chan gopacket.Packet
}

func listenPackets(sub chan gopacket.Packet) tea.Cmd {
	return func() tea.Msg {
		return pktMsg{<-sub}
	}
}

func (m model) Init() tea.Cmd {
	return listenPackets(m.sub)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case pktMsg:
    	summary := fmt.Sprintf("[%s] %s",
    		time.Now().Format("15:04:05"),
    		msg.packet.String(),
    	)
    	m.packets = append(m.packets, summary)
    	if len(m.packets) > 10 {
    		m.packets = m.packets[1:]
    	}

		return m, listenPackets(m.sub)
	}
	return m, nil
}

func (m model) View() string {
	s := "--- Got Your ___ ---\n\n"
	for _, p := range m.packets {
		s += p + "\n"
	}
	return s
}

func main() {
	packetChan := make(chan gopacket.Packet)

	go func() {
		device := "wlp15s0"
		snapshotLen := int32(1024)
		promiscuous := true
		timeout := 30 * time.Second

		handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range packetSource.Packets() {
			packetChan <- pkt
		}
	}()

	p := tea.NewProgram(model{
		packets: []string{},
		sub:	 packetChan,
	})

	if _, err := p.Run(); err != nil {
		fmt.Printf("error: %v", err)
		os.Exit(1)
	}
}
