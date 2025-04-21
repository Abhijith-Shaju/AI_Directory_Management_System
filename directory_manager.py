import os
import shutil
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import sys
import threading
import magic
from typing import List, Dict

class DirectoryManager:
    def __init__(self):
        self.file_categories = {
            'Images': {'JPEG': ['.jpg', '.jpeg'], 'PNG': ['.png'], 'GIF': ['.gif'], 'BMP': ['.bmp'], 'Other': []},
            'Documents': {'PDF': ['.pdf'], 'Word': ['.doc', '.docx'], 'Text': ['.txt'], 'Other': []},
            'Spreadsheets': {'Excel': ['.xls', '.xlsx'], 'CSV': ['.csv'], 'Other': []},
            'Presentations': {'PowerPoint': ['.ppt', '.pptx'], 'Other': []},
            'Archives': {'ZIP': ['.zip'], 'RAR': ['.rar'], '7z': ['.7z'], 'Other': []},
            'Audio': {'MP3': ['.mp3'], 'WAV': ['.wav'], 'Other': []},
            'Video': {'MP4': ['.mp4'], 'AVI': ['.avi'], 'Other': []},
            'Executables': {'Windows': ['.exe', '.msi'], 'Other': []},
            'Code': {'Python': ['.py'], 'JavaScript': ['.js'], 'Other': []},
            'Other': {'Other': []}
        }

        self.mime = magic.Magic(mime=True)
        self.created_folders = []  # Track folders created by the manager
        self.undo_stack = []  # Stack to track undo operations

    def create_folder(self, folder_path: str) -> bool:
        """Create folder if it doesn't exist and track it"""
        if not os.path.exists(folder_path):
            try:
                os.makedirs(folder_path)
                self.created_folders.append(folder_path)
                return True
            except Exception:
                return False
        return True

    def move_file(self, source_path: str, destination_path: str) -> bool:
        """Move file and create necessary folders"""
        try:
            if os.path.isdir(source_path):
                if not self.create_folder(destination_path):
                    return False
            
            shutil.move(source_path, destination_path)
            self.undo_stack.append((destination_path, source_path))
            return True
        except Exception as e:
            print(f"Move failed: {str(e)}")
            return False

    def scan_directory(self, path: str) -> List[Dict]:
        """Scan directory and return file information"""
        if not os.path.isdir(path):
            raise ValueError("Invalid directory path")

        files = []
        for root, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                try:
                    files.append({
                        'path': file_path,
                        'size': os.path.getsize(file_path),
                        'name': filename,
                        'mime': self.mime.from_file(file_path)
                    })
                except Exception as e:
                    print(f"Error scanning {file_path}: {str(e)}")
        return files

    def classify_file(self, path: str) -> tuple:
        """Classify file based on extension"""
        ext = os.path.splitext(path)[1].lower()
        for main_category, subcategories in self.file_categories.items():
            for subcategory, extensions in subcategories.items():
                if ext in extensions:
                    return (main_category, subcategory)
        return ('Other', 'Other')

    def organize_files(self, files: List[Dict], base_path: str) -> Dict:
        """Organize files into categorized folders"""
        results = {'moved': 0, 'errors': 0}

        for file_info in files:
            try:
                main_category, subcategory = self.classify_file(file_info['path'])
                main_dir = os.path.join(base_path, main_category)
                sub_dir = os.path.join(main_dir, subcategory)
                
                if not (self.create_folder(main_dir) and self.create_folder(sub_dir)):
                    results['errors'] += 1
                    continue

                new_path = os.path.join(sub_dir, os.path.basename(file_info['path']))
                if self.move_file(file_info['path'], new_path):
                    results['moved'] += 1
                else:
                    results['errors'] += 1
                    
            except Exception as e:
                print(f"Error moving file: {str(e)}")
                results['errors'] += 1

        return results

    def find_duplicates(self, file_paths: List[str]) -> Dict[str, List[str]]:
        """Find duplicate files based on MD5 hash"""
        hashes = {}
        duplicates = {}

        for path in file_paths:
            try:
                file_hash = self._file_hash(path)
                if file_hash in hashes:
                    if file_hash not in duplicates:
                        duplicates[file_hash] = [hashes[file_hash]]
                    duplicates[file_hash].append(path)
                else:
                    hashes[file_hash] = path
            except Exception as e:
                print(f"Duplicate check error: {str(e)}")
        return duplicates

    def _file_hash(self, path: str) -> str:
        """Calculate MD5 hash of a file"""
        hash_md5 = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def undo_last_operation(self) -> bool:
        """Undo the last file move operation"""
        if not self.undo_stack:
            return False

        success = True
        for new_path, original_path in reversed(self.undo_stack):
            try:
                shutil.move(new_path, original_path)
                
                # Clean up empty directories
                folder = os.path.dirname(new_path)
                if folder in self.created_folders and not os.listdir(folder):
                    os.rmdir(folder)
                    self.created_folders.remove(folder)
                    
                self.undo_stack.remove((new_path, original_path))
            except Exception as e:
                print(f"Undo failed: {str(e)}")
                success = False
                
        return success


class DirectoryManagerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Smart Directory Manager")
        self.geometry("900x600")
        self.configure(bg="#f0f0f0")
        self.resizable(True, True)
        
        self.manager = DirectoryManager()
        self.selected_path = ""
        
        self.style = ttk.Style()
        self.create_widgets()
        self.setup_styles()

    def setup_styles(self):
        """Configure default styles"""
        self.style.configure(".", background="#f0f0f0", foreground="black")
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", foreground="black")
        self.style.configure("Treeview", background="white", fieldbackground="white", foreground="black")

    def create_widgets(self):
        """Create all GUI components"""
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header_frame, text="Directory Manager").pack(side=tk.LEFT)
        
        # Path selection
        path_frame = ttk.Frame(main_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        self.path_entry = ttk.Entry(path_frame, width=60)
        self.path_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.select_directory)
        browse_btn.pack(side=tk.LEFT)
        
        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Scan", command=self.scan_directory).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Organize", command=self.organize_files).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Find Duplicates", command=self.find_duplicates).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Preview Changes", command=self.preview_changes).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Undo", command=self.undo_last_action).pack(side=tk.LEFT, padx=2)
        
        # File display treeview
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview with scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.tree = ttk.Treeview(tree_frame, columns=("size", "type", "new_location"), 
                                yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set,
                                selectmode="extended")
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        tree_scroll_y.config(command=self.tree.yview)
        tree_scroll_x.config(command=self.tree.xview)
        
        # Configure tree columns
        self.tree.heading("#0", text="File Name", anchor=tk.W)
        self.tree.heading("size", text="Size", anchor=tk.W)
        self.tree.heading("type", text="Type", anchor=tk.W)
        self.tree.heading("new_location", text="New Location", anchor=tk.W)
        
        self.tree.column("#0", width=250, stretch=tk.YES)
        self.tree.column("size", width=100, stretch=tk.NO)
        self.tree.column("type", width=150, stretch=tk.NO)
        self.tree.column("new_location", width=250, stretch=tk.YES)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(5, 0))
        self.progress.pack_forget()

    def select_directory(self):
        """Handle directory selection"""
        path = filedialog.askdirectory()
        if path:
            self.selected_path = path
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)
            
    def scan_directory(self):
        """Scan and display files"""
        if not self.selected_path:
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        self.tree.delete(*self.tree.get_children())
        self.status_var.set("Scanning directory...")
        self.progress.pack(fill=tk.X, pady=(5, 0))
        self.progress.start()
        
        threading.Thread(target=self._perform_scan, daemon=True).start()
        
    def _perform_scan(self):
        """Perform the actual scan in background"""
        try:
            files = self.manager.scan_directory(self.selected_path)
            total_size = sum(f['size'] for f in files)
            
            self.after(0, self._update_scan_results, files, total_size)
            
        except Exception as e:
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.after(0, self.progress.stop)
            self.after(0, self.progress.pack_forget)
            
    def _update_scan_results(self, files, total_size):
        """Update the treeview with scan results"""
        for file_info in files:
            main_category, subcategory = self.manager.classify_file(file_info['path'])
            self.tree.insert('', 'end', 
                text=file_info['name'],
                values=(
                    self.format_size(file_info['size']),
                    f"{main_category}/{subcategory}",
                    ""
                ),
                tags=(file_info['path'],)
            )
        self.status_var.set(f"Found {len(files)} files ({self.format_size(total_size)})")
        
    def organize_files(self):
        """Organize files into categories"""
        if not self.selected_path:
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        if not messagebox.askyesno("Confirm", "Organize files into categories?"):
            return
            
        self.status_var.set("Organizing files...")
        self.progress.pack(fill=tk.X, pady=(5, 0))
        self.progress.start()
        
        threading.Thread(target=self._perform_organization, daemon=True).start()
        
    def _perform_organization(self):
        """Perform file organization in background"""
        try:
            files = []
            for item in self.tree.get_children():
                path = self.tree.item(item, 'tags')[0]
                files.append({
                    'path': path,
                    'name': self.tree.item(item, 'text')
                })
            
            results = self.manager.organize_files(files, self.selected_path)
            self.after(0, self._update_organization_results, results['moved'], len(files))
            
        except Exception as e:
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.after(0, self.progress.stop)
            self.after(0, self.progress.pack_forget)
            
    def _update_organization_results(self, organized, total):
        """Update status after organization"""
        self.status_var.set(f"Organized {organized} of {total} files")
        self.scan_directory()  # Refresh the view
        
    def undo_last_action(self):
        """Undo the last file organization operation"""
        if not messagebox.askyesno("Confirm", "Undo last organization operation?"):
            return
            
        self.status_var.set("Undoing last operation...")
        self.progress.pack(fill=tk.X, pady=(5, 0))
        self.progress.start()
        
        threading.Thread(target=self._perform_undo, daemon=True).start()
        
    def _perform_undo(self):
        """Perform undo operation in background"""
        try:
            success = self.manager.undo_last_operation()
            if success:
                self.after(0, lambda: self.status_var.set("Undo successful"))
                self.after(0, self.scan_directory)
            else:
                self.after(0, lambda: self.status_var.set("Nothing to undo"))
        except Exception as e:
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.after(0, self.progress.stop)
            self.after(0, self.progress.pack_forget)
        
    def find_duplicates(self):
        """Find duplicate files"""
        if not self.selected_path:
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        self.status_var.set("Finding duplicates...")
        self.progress.pack(fill=tk.X, pady=(5, 0))
        self.progress.start()
        
        threading.Thread(target=self._perform_duplicate_check, daemon=True).start()
        
    def _perform_duplicate_check(self):
        """Perform duplicate file checking in background"""
        try:
            file_paths = []
            for item in self.tree.get_children():
                path = self.tree.item(item, 'tags')[0]
                file_paths.append(path)
            
            duplicates = self.manager.find_duplicates(file_paths)
            self.after(0, self._display_duplicates, duplicates)
            
        except Exception as e:
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.after(0, self.progress.stop)
            self.after(0, self.progress.pack_forget)
            
    def _display_duplicates(self, duplicates):
        """Show duplicate files in a new window"""
        if not duplicates:
            messagebox.showinfo("No Duplicates", "No duplicate files found")
            return
            
        dup_window = tk.Toplevel(self)
        dup_window.title("Duplicate Files")
        dup_window.geometry("800x600")
        
        tree = ttk.Treeview(dup_window, columns=("size", "path"), selectmode="extended")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tree.heading("#0", text="Hash")
        tree.heading("size", text="Size")
        tree.heading("path", text="Path")
        
        tree.column("#0", width=200)
        tree.column("size", width=100)
        tree.column("path", width=400)
        
        for hash_val, paths in duplicates.items():
            parent = tree.insert("", "end", text=hash_val[:8] + "...")
            for path in paths:
                size = os.path.getsize(path)
                tree.insert(parent, "end", values=(
                    self.format_size(size),
                    path
                ))
        
        btn_frame = ttk.Frame(dup_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Button(btn_frame, text="Delete Selected", 
                  command=lambda: self._delete_selected_duplicates(tree)).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Close", 
                  command=dup_window.destroy).pack(side=tk.RIGHT)
        
    def _delete_selected_duplicates(self, tree):
        """Delete selected duplicate files"""
        selected = tree.selection()
        if not selected:
            return
            
        to_delete = []
        for item in selected:
            if tree.parent(item):
                to_delete.append(tree.item(item, "values")[1])
        
        if not to_delete:
            return
            
        if not messagebox.askyesno("Confirm", f"Delete {len(to_delete)} selected files?"):
            return
            
        deleted = 0
        for path in to_delete:
            try:
                os.remove(path)
                deleted += 1
            except Exception as e:
                print(f"Error deleting {path}: {str(e)}")
                
        messagebox.showinfo("Complete", f"Deleted {deleted} of {len(to_delete)} files")
        tree.winfo_toplevel().destroy()
        self.find_duplicates()
        
    def preview_changes(self):
        """Show preview of organization changes"""
        if not self.selected_path:
            messagebox.showerror("Error", "Please select a directory first")
            return
            
        preview_window = tk.Toplevel(self)
        preview_window.title("Preview Changes")
        preview_window.geometry("700x500")
        
        preview_text = scrolledtext.ScrolledText(preview_window, wrap=tk.WORD)
        preview_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        preview_text.insert(tk.END, "Preview of organization changes:\n\n")
        
        for item in self.tree.get_children():
            path = self.tree.item(item, 'tags')[0]
            filename = self.tree.item(item, 'text')
            main_category, subcategory = self.manager.classify_file(path)
            
            preview_text.insert(tk.END, 
                f"{filename}\n  From: {os.path.dirname(path)}\n  To:   {main_category}/{subcategory}\n\n")
        
        preview_text.config(state=tk.DISABLED)
        
    @staticmethod
    def format_size(size):
        """Convert bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

if __name__ == "__main__":
    # Windows-specific console hiding
    if sys.platform == 'win32':
        try:
            from ctypes import windll
            windll.user32.ShowWindow(windll.kernel32.GetConsoleWindow(), 0)
        except Exception as e:
            print(f"Console hide failed: {e}")

    app = DirectoryManagerGUI()
    app.mainloop()
