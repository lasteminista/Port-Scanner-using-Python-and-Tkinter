import socket
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, font, scrolledtext
from tkinter.filedialog import asksaveasfilename
from ctypes import windll


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        # Default : common ports
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]

        # Default : common ports (shared variable for the radio buttons)
        self.var = tk.IntVar(value=1)

        # Initial values for target, ports and results list
        self.target = ''
        self.ports = list()
        self.results = list()

        # Configure the Root Window
        self.title("My Port Scanner")
        self.geometry("820x550")
        self.resizable(0, 0)

        # Get default background
        self.defaultbg = self.cget('bg')

        # Set default Font
        self.def_font = tk.font.nametofont("TkDefaultFont")
        self.def_font.config(family="Segoe Script", size=13, weight=font.BOLD)

        # Port Scanner title
        ttk.Label(self, text="My Port Scanner", font=("Segoe Script", 17, "bold"))\
            .grid(column=0, row=0, columnspan=4)

        # Label Hostname
        ttk.Label(self, text="Enter your target : ").grid(column=0, row=1)

        # Entry Hostname
        self.hostname = ttk.Entry(self, font="TkDefaultFont")
        self.hostname.insert(tk.END, 'localhost')
        self.hostname.grid(column=1, row=1, sticky=tk.EW, columnspan=3)

        # Get ports : common, list or range
        self.option_port_common = ttk.Radiobutton(self, text="Common Ports", variable=self.var, value=1,
                                                  command=lambda v=self.var: self.select_ports(v))
        self.option_port_common.grid(column=0, row=2, sticky=tk.W)
        self.option_port_list = ttk.Radiobutton(self, text="Ports List", variable=self.var, value=2,
                                                command=lambda v=self.var: self.select_ports(v))
        self.option_port_list.grid(column=0, row=3, sticky=tk.W)
        self.option_port_range = ttk.Radiobutton(self, text="Ports Range", variable=self.var, value=3,
                                                 command=lambda v=self.var: self.select_ports(v))
        self.option_port_range.grid(column=0, row=4, sticky=tk.W)

        # Port entries
        self.port_common_entry = ttk.Entry(self, font="TkDefaultFont")
        self.port_common_entry.insert(0, str(self.common_ports)[1:-1])
        self.port_common_entry.config(state='readonly')
        self.port_common_entry.grid(column=1, row=2, sticky=tk.EW, columnspan=3)

        self.port_list_entry = ttk.Entry(self, font="TkDefaultFont")
        self.port_list_entry.config(state='disabled')
        self.port_list_entry.grid(column=1, row=3, sticky=tk.EW, columnspan=3)

        self.port_range_entry_1 = ttk.Entry(self, font="TkDefaultFont")
        self.port_range_entry_1.grid(column=1, row=4, sticky=tk.W)
        self.port_range_entry_1.config(state='disabled')

        ttk.Label(self, text="-").grid(column=2, row=4, sticky=tk.W)

        self.port_range_entry_2 = ttk.Entry(self, font="TkDefaultFont")
        self.port_range_entry_2.config(state='disabled')
        self.port_range_entry_2.grid(column=3, row=4, sticky=tk.W)

        # Port Options
        self.port_entries = [self.port_common_entry,
                             self.port_list_entry,
                             self.port_range_entry_1, self.port_range_entry_2]

        # Scan Button
        scan_button = ttk.Button(self, text="Scan Target", command=self.port_scanner)
        scan_button.grid(column=1, row=5, columnspan=3, sticky=tk.EW)

        # Results Label
        ttk.Label(self, text="Results : ").grid(column=0, row=7, sticky=tk.EW)

        # Results Area
        self.results_area = scrolledtext.ScrolledText(self, width=30, height=5, font="TkDefaultFont")
        self.results_area.grid(column=1, row=7, columnspan=3, pady=10, padx=10, sticky=tk.EW)
        self.results_area.config(state='disabled')

        # Save Results Button
        self.save_button = ttk.Button(self, text="Save Results", command=self.save_results)
        self.save_button.grid(column=1, row=9, columnspan=3, sticky=tk.EW)
        self.save_button.config(state='disabled')

        # Set default padding for all widgets
        for widget in self.winfo_children():
            if widget.grid_info()['column'] == 0:
                widget.grid(padx=25)
            widget.grid(pady=5)

    # Get Target Value
    def get_target(self):
        try:
            target = socket.gethostbyname(self.hostname.get())
        except socket.gaierror:
            return False
        except socket.error:
            return False
        except UnicodeError:
            return False
        else:
            ttk.Label(self, text=" Scan target : " + target, background=self.defaultbg)\
                .grid(column=1, row=6, columnspan=3, sticky=tk.EW)
            return target

    # Enable Ports Selection
    def select_ports(self, v):
        if v.get() == 1:
            for p in self.port_entries:
                if p != self.port_common_entry:
                    p.configure(state='disabled')
                else:
                    p.configure(state='readonly')
        if v.get() == 2:
            for p in self.port_entries:
                if p != self.port_list_entry:
                    p.configure(state='disabled')
                else:
                    p.configure(state='normal')
        if v.get() == 3:
            for p in self.port_entries:
                if p != self.port_common_entry and p != self.port_list_entry:
                    p.configure(state='normal')
                else:
                    p.configure(state='disabled')

    # Return Selected Ports List
    def port_list(self):
        self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        ports = list()
        port_selection = self.var.get()
        if port_selection == 1:
            ports = self.common_ports
        if port_selection == 2 and self.port_list_entry.get() != '':
            try:
                ports = list(map(int, self.port_list_entry.get().split(',')))
            except ValueError:
                return False
        if port_selection == 3 and self.port_range_entry_1.get().isdigit() and self.port_range_entry_2.get().isdigit():
            if self.port_range_entry_1.get() < self.port_range_entry_2.get():
                try:
                    ports = list(range(int(self.port_range_entry_1.get()), int(self.port_range_entry_2.get())+1))
                except ValueError:
                    return False
            else:
                return False

        if ports:
            valid_ports = all(p in list(range(0, 65535)) for p in ports)
            if valid_ports:
                return ports
            else:
                return False

    # Scan a Single Port
    def scan_port(self, target, port):
        # Create a socket object
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            test = s.connect_ex((target, port))
            if test == 0:
                result = f' Port {port} is [open] \n'
                self.results.append(result)

    # Port Scanner
    def port_scanner(self):

        self.target = self.get_target()
        self.ports = self.port_list()

        if self.target and self.ports:
            thread_list = list()
            self.results.clear()
            start_time = datetime.now()

            for port in self.ports:
                scan = threading.Thread(target=self.scan_port, args=(self.target, port))
                thread_list.append(scan)
                scan.daemon = True
                scan.start()

            for scan in thread_list:
                scan.join()

            self.results_area.configure(state='normal')
            self.results_area.delete('1.0', tk.END)
            for r in self.results:
                self.results_area.insert(tk.INSERT, r)
            self.results_area.configure(state='disabled')

            end_time = datetime.now()
            ttk.Label(self, text=" Scanning completed in "+str(end_time - start_time),
                      foreground='green', background='light green')\
                .grid(column=1, row=8, columnspan=3, sticky=tk.EW)
            self.save_button.config(state='normal')
        else:
            ttk.Label(self, text=" Oops ! Looks like you did something wrong !",
                      foreground='red', background='pink') \
                .grid(column=1, row=8, columnspan=3, sticky=tk.EW)
            self.save_button.config(state='disabled')

    # Write results in file
    def write_file(self, file):
        with open(file, 'w') as f:
            f.write("Port scanner results : \n")
            f.write("-"*22 + "\n")
            f.write(f" Target : \t {self.target} \n")
            if self.var.get() != 3:
                f.write(f" Ports : \t {str(self.ports)} \n")
            else:
                f.write(f" Ports : \t "
                        f"[{str(self.port_range_entry_1.get())} - {str(self.port_range_entry_2.get())}]\n")
            f.write(f"\n Results : \t {str(len(self.results))}/{str(len(self.ports))} \n")
            f.write(f"{str(self.results_area.get('1.0', tk.END))}")

    # Save results in file
    def save_results(self):
        file = asksaveasfilename(defaultextension=".txt",
                                 initialfile=f'Scan_Results_{datetime.now().strftime("%Y%m%d-%H%M%S")}.txt')
        if file:
            self.write_file(file)


if __name__ == "__main__":
    app = App()
    windll.shcore.SetProcessDpiAwareness(1)
    app.mainloop()
