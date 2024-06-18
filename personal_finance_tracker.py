# pylint: disable=missing-class-docstring
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring

import mysql.connector as mysql
import bcrypt
from datetime import date, datetime
import pandas as pd
import matplotlib.pyplot as plt
from tkinter import *
from tkinter import messagebox, ttk
from tkinter import filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class DatabaseManager:
    def __init__(self):
        try:
            self.mydb = mysql.connect(host='localhost', user='root', password='root', database='personal_finance_tracker')
            self.mycursor = self.mydb.cursor(buffered=True)
            self.create_tables()
        except Exception as e:
            print(e)

    def create_tables(self):
        tables = ["CREATE TABLE IF NOT EXISTS account (username VARCHAR(255), password CHAR(255))",
                  "CREATE TABLE IF NOT EXISTS transactions (amount FLOAT, date DATE, description VARCHAR(255), category VARCHAR(255), type VARCHAR(255))",
                  "CREATE TABLE IF NOT EXISTS budgets (username VARCHAR(255), monthly_budget FLOAT)"]
        for table in tables:
            self.execute_query(table, ())

    def execute_query(self, query, params):
        try:
            self.mycursor.execute(query, params)
            self.mydb.commit()
            return True
        except Exception as e:
            print(e)
            self.mydb.rollback()
            return False

    def fetch_data(self, query, params):
        try:
            self.mycursor.execute(query, params)
            result = self.mycursor.fetchall()
            return result
        except Exception as e:
            print(e)
            return None

db = DatabaseManager()

class User:
    def __init__(self):
        self.__is_login = False
        self.username = None

    def create_account(self, username: str, password: str) -> bool:
        password = password.encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt(10))
        return db.execute_query("INSERT INTO account VALUES (%s, %s)", (username, hashed))

    def login(self, username: str, password: str) -> bool:
        if not username or not password:
            raise TypeError("Username and password cannot be empty!!!")
        result = db.fetch_data("SELECT * FROM account WHERE username=%s", (username,))
        if result is None:
            return False
        try:
            hashed = result[0][1].encode('utf-8')
            if not bcrypt.checkpw(password.encode('utf-8'), hashed):
                return False
            self.__is_login = True
            self.username = username
            return True
        except Exception as e:
            print(e)
            return False

    def logout(self) -> bool:
        self.__is_login = False
        self.username = None
        return True

    def check_status(self)->bool:
        return self.__is_login

    def set_budget(self, monthly_budget: float) -> bool:
        if monthly_budget <= 0:
            raise ValueError("Budget must be a positive number.")
        return db.execute_query("INSERT INTO budgets (username, monthly_budget) VALUES (%s, %s) ON DUPLICATE KEY UPDATE monthly_budget=%s", (self.username, monthly_budget, monthly_budget))

    def get_budget(self) -> float:
        result = db.fetch_data("SELECT monthly_budget FROM budgets WHERE username=%s", (self.username,))
        if result:
            return result[0][0]
        else:
            return 0

class Transaction:
    def __init__(self):
        pass

    def add_transaction(self, amount: float, date: date, description: str, category: str, type: str) -> bool:
        if amount <= 0:
            raise ValueError("Amount must be a positive number.")
        return db.execute_query("INSERT INTO transactions VALUES (%s, %s, %s, %s, %s)", (amount, date, description, category, type))

class Report:
    def __init__(self):
        pass

    def generate_report(self, start_date: date, end_date: date):
        if start_date > end_date:
            raise ValueError("Start date cannot be after end date.")
        transactions = db.fetch_data("SELECT * FROM transactions WHERE date BETWEEN %s AND %s", (start_date, end_date))
        if transactions is None:
            return None
        # Generate the report based on the transactions
        report = pd.DataFrame(transactions, columns=['Amount', 'Date', 'Description', 'Category', 'Type'])
        return report

    def generate_pie_chart(self, username: str):
        transactions = db.fetch_data("SELECT * FROM transactions", ())
        if transactions is None:
            return None

        budget_result = db.fetch_data("SELECT monthly_budget FROM budgets WHERE username=%s", (username,))
        monthly_budget = budget_result[0][0] if budget_result else 0

        df = pd.DataFrame(transactions, columns=['Amount', 'Date', 'Description', 'Category', 'Type'])
        current_month = datetime.now().strftime("%Y-%m")
        df['Date'] = pd.to_datetime(df['Date'])
        df['Month'] = df['Date'].dt.strftime("%Y-%m")
        df = df[df['Month'] == current_month]

        total_expense = df['Amount'].sum()
        remaining_budget = max(monthly_budget - total_expense, 0)

        summary = df.groupby('Category')['Amount'].sum().reset_index()
        summary.loc[len(summary.index)] = ['Remaining Budget', remaining_budget]  # Add remaining budget as a category
        
        # Fix percentage calculation
        if monthly_budget > 0:
            summary['Percentage'] = (summary['Amount'] / monthly_budget) * 100
        else:
            summary['Percentage'] = 0  # Set to 0 if no budget set to avoid inf

        # Plotting the donut chart
        fig, ax = plt.subplots()
        fig.subplots_adjust(left=0.37, right=1.15)
        colors = plt.cm.Paired(range(len(summary)))
        wedges, texts = ax.pie(summary['Amount'], colors=colors, startangle=90, counterclock=False, wedgeprops=dict(width=0.3))
        ax.axis('equal')

        # Add the title in the center
        plt.text(0, 0, 'Monthly Budget\nand Expenses', ha='center', va='center', fontsize=12)

        # Add a legend
        legend_labels = [f'{row["Category"]}: ${row["Amount"]:.2f} ({row["Percentage"]:.2f}%)' for index, row in summary.iterrows()]
        legend_labels = [label.split(': ') for label in legend_labels]  # Split for better formatting
        legend_labels_formatted = [f'{l[0]:<20} {l[1]}' for l in legend_labels]  # Align text

        ax.legend(wedges, legend_labels_formatted, title="Categories", bbox_to_anchor=(-0.5, 1), loc="upper left", frameon=False)

        return fig
        transactions = db.fetch_data("SELECT * FROM transactions", ())
        if transactions is None:
            return None
    
        budget_result = db.fetch_data("SELECT monthly_budget FROM budgets WHERE username=%s", (username,))
        monthly_budget = budget_result[0][0] if budget_result else 0
    
        df = pd.DataFrame(transactions, columns=['Amount', 'Date', 'Description', 'Category', 'Type'])
        current_month = datetime.now().strftime("%Y-%m")
        df['Date'] = pd.to_datetime(df['Date'])
        df['Month'] = df['Date'].dt.strftime("%Y-%m")
        df = df[df['Month'] == current_month]
    
        total_expense = df['Amount'].sum()
        remaining_budget = max(monthly_budget - total_expense, 0)
    
        summary = df.groupby('Category')['Amount'].sum().reset_index()
        summary.loc[len(summary.index)] = ['Remaining Budget', remaining_budget]  # Add remaining budget as a category
        
        # Fix percentage calculation
        if monthly_budget > 0:
            summary['Percentage'] = (summary['Amount'] / monthly_budget) * 100
        else:
            summary['Percentage'] = 0  # Set to 0 if no budget set to avoid inf
    
        # Plotting the donut chart
        colors = plt.cm.Paired(range(len(summary)))
        wedges, texts = ax.pie(summary['Amount'], colors=colors, startangle=90, counterclock=False, wedgeprops=dict(width=0.3))
        ax.axis('equal')
    
        # Add the title in the center
        plt.text(0, 0, 'Monthly Budget\nand Expenses', ha='center', va='center', fontsize=12)
    
        # Add a legend
        legend_labels = [f'{row["Category"]}: ${row["Amount"]:.2f} ({row["Percentage"]:.2f}%)' for index, row in summary.iterrows()]
        legend_labels = [label.split(': ') for label in legend_labels]  # Split for better formatting
        legend_labels_formatted = [f'{l[0]:<20} {l[1]}' for l in legend_labels]  # Align text
    
        ax.legend(wedges, legend_labels_formatted, title="Categories", bbox_to_anchor=(1, 1), loc="upper left", frameon=False)
    
        return fig

class Data:
    def __init__(self):
        pass

    def export_data(self, file_path: str, file_format: str) -> bool:
        if file_format not in ['csv', 'xlsx']:
            raise ValueError("Invalid file format. Choose either 'csv' or 'xlsx'.")
        # Export the data to the specified file path
        data = db.fetch_data("SELECT * FROM transactions", ())
        if data is None:
            return False
        df = pd.DataFrame(data, columns=['Amount', 'Date', 'Description', 'Category', 'Type'])
        if file_format == 'csv':
            df.to_csv(file_path, index=False)
        else:
            df.to_excel(file_path, index=False)
        return True

    def import_data(self, file_path: str, file_format: str) -> bool:
        if file_format not in ['csv', 'xlsx']:
            raise ValueError("Invalid file format. Choose either 'csv' or 'xlsx'.")
        # Import the data from the specified file path
        if file_format == 'csv':
            df = pd.read_csv(file_path)
        else:
            df = pd.read_excel(file_path)
        for index, row in df.iterrows():
            db.execute_query("INSERT INTO transactions VALUES (%s, %s, %s, %s, %s)", (row['Amount'], row['Date'], row['Description'], row['Category'], row['Type']))
        return True

class GUI:
    def __init__(self, title: str = "PFT", geometry: str = "800x600", resizable: tuple = (True, True))->None:
        self.user = User()
        self.transaction = Transaction()
        self.category = Category()
        self.report = Report()
        self.data = Data()

        self.window = Tk()
        self.window.title(title)
        self.window.geometry(geometry)
        self.window.resizable(*resizable)
        self.main_menu()
        
    def main_menu(self)->None:
        self.clear()
        Label(self.window, text="Personal Finance Tracker", font=("Helvetica", 20, "bold")).pack(pady=20)
        Button(self.window, text="Login", command=self.login_menu, width=20).pack(pady=10)
        Button(self.window, text="Create Account", command=self.create_account_menu, width=20).pack(pady=10)

    def clear(self)->None:
        for widget in self.window.winfo_children():
            widget.destroy()

    def login_menu(self)->None:
        self.clear()
        Label(self.window, text="Login", font=("Helvetica", 16, "bold")).pack(pady=20)
        Label(self.window, text="Username").pack(pady=5)
        username_entry = Entry(self.window)
        username_entry.pack(pady=5)
        Label(self.window, text="Password").pack(pady=5)
        password_entry = Entry(self.window, show="*")
        password_entry.pack(pady=5)
        Button(self.window, text="Login", command=lambda: self.login(username_entry.get(), password_entry.get())).pack(pady=20)
        Button(self.window, text="Back", command=self.main_menu).pack(pady=10)

    def create_account_menu(self)->None:
        self.clear()
        Label(self.window, text="Create Account", font=("Helvetica", 16, "bold")).pack(pady=20)
        Label(self.window, text="Username").pack(pady=5)
        username_entry = Entry(self.window)
        username_entry.pack(pady=5)
        Label(self.window, text="Password").pack(pady=5)
        password_entry = Entry(self.window, show="*")
        password_entry.pack(pady=5)
        Button(self.window, text="Create Account", command=lambda: self.create_account(username_entry.get(), password_entry.get())).pack(pady=20)
        Button(self.window, text="Back", command=self.main_menu).pack(pady=10)

    def user_menu(self)->None:
        self.clear()
        Label(self.window, text=f"Welcome, {self.user.username}!", font=("Helvetica", 16, "bold")).pack(pady=20)
        Button(self.window, text="Add Transaction", command=self.add_transaction_menu, width=20).pack(pady=10)
        Button(self.window, text="Generate Report", command=self.generate_report_menu, width=20).pack(pady=10)
        Button(self.window, text="Export Data", command=self.export_data_menu, width=20).pack(pady=10)
        Button(self.window, text="Import Data", command=self.import_data_menu, width=20).pack(pady=10)
        Button(self.window, text="Set Budget", command=self.set_budget_menu, width=20).pack(pady=10)
        Button(self.window, text="Generate Pie Chart", command=self.generate_pie_chart_menu, width=20).pack(pady=10)
        Button(self.window, text="Logout", command=self.logout, width=20).pack(pady=10)

    def add_transaction_menu(self)->None:
        self.clear()
        Label(self.window, text="Add Transaction", font=("Helvetica", 16, "bold")).pack(pady=20)
        Label(self.window, text="Amount").pack(pady=5)
        amount_entry = Entry(self.window)
        amount_entry.pack(pady=5)
        Label(self.window, text="Date (YYYY-MM-DD)").pack(pady=5)
        date_entry = Entry(self.window)
        date_entry.pack(pady=5)
        Label(self.window, text="Description").pack(pady=5)
        description_entry = Entry(self.window)
        description_entry.pack(pady=5)
        Label(self.window, text="Category").pack(pady=5)
        category_entry = Entry(self.window)
        category_entry.pack(pady=5)
        Label(self.window, text="Type").pack(pady=5)
        type_entry = Entry(self.window)
        type_entry.pack(pady=5)
        Button(self.window, text="Add Transaction", command=lambda: self.add_transaction(float(amount_entry.get()), date_entry.get(), description_entry.get(), category_entry.get(), type_entry.get())).pack(pady=20)
        Button(self.window, text="Back", command=self.user_menu).pack(pady=10)

    def generate_report_menu(self)->None:
        self.clear()
        Label(self.window, text="Generate Report", font=("Helvetica", 16, "bold")).pack(pady=20)
        Label(self.window, text="Start Date (YYYY-MM-DD)").pack(pady=5)
        start_date_entry = Entry(self.window)
        start_date_entry.pack(pady=5)
        Label(self.window, text="End Date (YYYY-MM-DD)").pack(pady=5)
        end_date_entry = Entry(self.window)
        end_date_entry.pack(pady=5)
        Button(self.window, text="Generate Report", command=lambda: self.generate_report(start_date_entry.get(), end_date_entry.get())).pack(pady=20)
        Button(self.window, text="Back", command=self.user_menu).pack(pady=10)

    def export_data_menu(self)->None:
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("Excel files", "*.xlsx")])
        if file_path:
            file_format = 'csv' if file_path.endswith('.csv') else 'xlsx'
            self.data.export_data(file_path, file_format)
            messagebox.showinfo("Export", "Data Exported Successfully")

    def import_data_menu(self)->None:
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("Excel files", "*.xlsx")])
        if file_path:
            file_format = 'csv' if file_path.endswith('.csv') else 'xlsx'
            self.data.import_data(file_path, file_format)
            messagebox.showinfo("Import", "Data Imported Successfully")

    def set_budget_menu(self)->None:
        self.clear()
        Label(self.window, text="Set Budget", font=("Helvetica", 16, "bold")).pack(pady=20)
        Label(self.window, text="Monthly Budget").pack(pady=5)
        budget_entry = Entry(self.window)
        budget_entry.pack(pady=5)
        Button(self.window, text="Set Budget", command=lambda: self.set_budget(float(budget_entry.get()))).pack(pady=20)
        Button(self.window, text="Back", command=self.user_menu).pack(pady=10)

    def generate_pie_chart_menu(self)->None:
        self.clear()
        Label(self.window, text="Monthly Budget and Expenses", font=("Helvetica", 16, "bold")).pack(pady=20)
        fig = self.report.generate_pie_chart(self.user.username)
        if fig:
            canvas = FigureCanvasTkAgg(fig, master=self.window)
            canvas.draw()
            canvas.get_tk_widget().pack()
        Button(self.window, text="Back", command=self.user_menu).pack(pady=20)

    def login(self, username: str, password: str)->None:
        if self.user.login(username, password):
            messagebox.showinfo("Success", "Login successful!")
            self.user_menu()
        else:
            messagebox.showerror("Error", "Invalid username or password!")

    def create_account(self, username: str, password: str)->None:
        if self.user.create_account(username, password):
            messagebox.showinfo("Success", "Account created successfully!")
            self.login_menu()
        else:
            messagebox.showerror("Error", "Failed to create account!")

    def add_transaction(self, amount: float, date: date, description: str, category: str, type: str)->None:
        if self.transaction.add_transaction(amount, date, description, category, type):
            messagebox.showinfo("Success", "Transaction added successfully!")
            self.user_menu()
        else:
            messagebox.showerror("Error", "Failed to add transaction!")

    def generate_report(self, start_date: date, end_date: date)->None:
        report_data = self.report.generate_report(start_date, end_date)
        if not report_data.empty:
            self.display_report(report_data)
        else:
            messagebox.showerror("Error", "Failed to generate report!")

    def display_report(self, report_data)->None:
        self.clear()
        Label(self.window, text="Report", font=("Helvetica", 16, "bold")).pack(pady=20)
        text_widget = Text(self.window)
        text_widget.configure(state="disabled")
        text_widget.pack(pady=10)
        text_widget.insert(END, report_data)
        Button(self.window, text="Back", command=self.user_menu).pack(pady=10)

    def set_budget(self, budget: float)->None:
        if self.user.set_budget(budget):
            messagebox.showinfo("Success", "Budget set successfully!")
            self.user_menu()
        else:
            messagebox.showerror("Error", "Failed to set budget!")

    def logout(self)->None:
        self.user.logout()
        messagebox.showinfo("Success", "Logged out successfully!")
        self.main_menu()


def main():
    gui = GUI()
    gui.window.mainloop()

if __name__ == "__main__":
    main()
