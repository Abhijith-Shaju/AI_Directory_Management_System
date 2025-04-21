# *Smart Directory Management System*
A Python-based AI-powered directory management tool that organizes files, detects duplicates, and provides undo functionality, all through an intuitive Tkinter-based GUI.

*Features*  
- **File Categorization:** Automatically categorizes files into folders such as "Images," "Documents," "Videos," and more.  
- **Duplicate Detection:** Finds duplicate files based on their SHA256 hash values.  
- **Undo Functionality:** Allows undoing the last file organization operation, reverting files to their original locations.  
- **User-Friendly GUI:** Built using Tkinter, the GUI allows users to easily scan directories, organize files, and manage duplicates.  

*Technologies Used*
- *Python*
- *Tkinter:* For building the graphical user interface.  
- *Hashlib:* For generating file hashes and detecting duplicates.  
- *OS and Shutil:* For file and directory management.  
- *PIL (Pillow):* For handling image metadata (if needed).  
- *Magic Library (python-magic):* For MIME type detection.  

---

*Installation Guide*

*Step 1: Clone the Repository* 
```bash  
git clone https://github.com/your-username/ai-directory-management-system.git  
cd ai-directory-management-system  
```  

*Step 2: Install Required Dependencies*  
Make sure you have Python installed (version 3.x recommended). Then, run:  
```bash  
pip install -r requirements.txt  
```  

*Step 3: Run the Program*
```bash  
python directory_manager.py  
```  

---

*How to Use the Application*  

1. *Scan a Directory:*
   - Select the folder you want to organize and click the **"Scan"** button to analyze its contents.  

2. *Organize Files:*
   - Once the directory is scanned, click **"Organize"** to categorize files into folders (Images, Documents, etc.).  

3. *Undo Last Action:*  
   - Accidentally moved the files to new folders? No worries! Click **"Undo"** to revert the last file organization action.  

4. *Detect Duplicates:*  
   - Use the **"Find Duplicates"** button to search for duplicate files in the scanned directory. You can then delete the duplicates if desired.  

5. *Preview Changes (Optional):*  
   - Before organizing files, click **"Preview Changes"** to see how the files will be reorganized.  

---

*Folder Categorization*  

By default, the tool categorizes files into the following categories:  

- *Images:* `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`  
- *Documents:* `.pdf`, `.doc`, `.docx`, `.txt`  
- *Spreadsheets:* `.xls`, `.xlsx`, `.csv`  
- *Presentations:* `.ppt`, `.pptx`  
- *Archives:* `.zip`, `.rar`, `.7z`  
- *Audio:* `.mp3`, `.wav`  
- *Video:* `.mp4`, `.avi`  
- *Executables:* `.exe`, `.msi`  
- *Code:* `.py`, `.js`  

Files with extensions not listed above are placed in an "Other" folder.  

---

*Project Structure*  

- *main.py:* Contains the core functionality and GUI code.  
- *README.md:* Documentation for the project.  
- *requirements.txt:* Lists the Python dependencies.  

---

*Contributing* 
Contributions are welcome! Please follow these steps:  
1. Fork the repository.  
2. Create a new branch (`git checkout -b feature-branch`).  
3. Commit your changes (`git commit -m "Add new feature"`).  
4. Push to your branch (`git push origin feature-branch`).  
5. Open a pull request on GitHub.  

---

*Contact*  
For any questions or suggestions, feel free to contact me at [abhijithshaju2004@gmail.com] or raise an issue on GitHub.  

---

*Acknowledgments*  
Special thanks to:  
- The developers of Tkinter, Pillow, and Python-Magic libraries.  
- The open-source community for inspiration and support.  
