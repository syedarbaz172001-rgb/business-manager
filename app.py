import streamlit as st
import sqlite3
import hashlib
import secrets
import html
from datetime import datetime, date
import pandas as pd


# =========================================================
# CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Business Manager",
    page_icon="💼",
    layout="wide"
)

DB_NAME = "business.db"


# =========================================================
# DATABASE
# =========================================================

def get_connection():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def setup_database():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            min_stock INTEGER DEFAULT 5,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            customer_id INTEGER,
            total REAL NOT NULL,
            payment_method TEXT,
            sale_date TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            subtotal REAL NOT NULL,
            FOREIGN KEY(sale_id) REFERENCES sales(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT,
            amount REAL NOT NULL,
            expense_date TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS stock_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            change_type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)

    conn.commit()
    conn.close()


setup_database()


# =========================================================
# PASSWORD SECURITY
# =========================================================

def hash_password(password):
    salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    ).hex()

    return f"{salt}${password_hash}"


def verify_password(password, stored_password):
    try:
        salt, stored_hash = stored_password.split("$")

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            120000
        ).hex()

        return secrets.compare_digest(password_hash, stored_hash)

    except Exception:
        return False


# =========================================================
# SESSION
# =========================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "user_id" not in st.session_state:
    st.session_state.user_id = None

if "user_name" not in st.session_state:
    st.session_state.user_name = None


# =========================================================
# AUTHENTICATION
# =========================================================

def register_user(name, email, password):
    conn = get_connection()

    try:
        conn.execute(
            """
            INSERT INTO users
            (name, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                name.strip(),
                email.strip().lower(),
                hash_password(password),
                datetime.now().isoformat()
            )
        )

        conn.commit()
        return True, "Account created successfully!"

    except sqlite3.IntegrityError:
        return False, "An account with this email already exists."

    finally:
        conn.close()


def login_user(email, password):
    conn = get_connection()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email.strip().lower(),)
    ).fetchone()

    conn.close()

    if user and verify_password(password, user["password_hash"]):
        return user

    return None


def logout():
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.user_name = None
    st.rerun()


# =========================================================
# LOGIN / SIGNUP PAGE
# =========================================================

def show_authentication():

    st.title("💼 Business Manager")
    st.subheader("Manage your business privately")

    login_tab, signup_tab = st.tabs(
        ["🔐 Login", "📝 Create Account"]
    )

    with login_tab:

        st.markdown("### Welcome back")

        email = st.text_input(
            "Email",
            key="login_email"
        )

        password = st.text_input(
            "Password",
            type="password",
            key="login_password"
        )

        if st.button(
            "Login",
            type="primary",
            use_container_width=True
        ):

            if not email or not password:
                st.error("Please enter your email and password.")

            else:
                user = login_user(email, password)

                if user:

                    st.session_state.logged_in = True
                    st.session_state.user_id = user["id"]
                    st.session_state.user_name = user["name"]

                    st.success("Login successful!")
                    st.rerun()

                else:
                    st.error("Incorrect email or password.")

    with signup_tab:

        st.markdown("### Create your business account")

        name = st.text_input(
            "Your name",
            key="signup_name"
        )

        email = st.text_input(
            "Email",
            key="signup_email"
        )

        password = st.text_input(
            "Password",
            type="password",
            key="signup_password"
        )

        confirm_password = st.text_input(
            "Confirm password",
            type="password",
            key="signup_confirm"
        )

        if st.button(
            "Create Account",
            type="primary",
            use_container_width=True
        ):

            if not name or not email or not password:
                st.error("Please fill all required fields.")

            elif password != confirm_password:
                st.error("Passwords do not match.")

            elif len(password) < 6:
                st.error("Password should contain at least 6 characters.")

            else:
                success, message = register_user(
                    name,
                    email,
                    password
                )

                if success:
                    st.success(message)
                    st.info("You can now log in.")
                else:
                    st.error(message)


# =========================================================
# HELPER
# =========================================================

def current_user_id():
    return st.session_state.user_id


def read_query(sql, params=()):
    conn = get_connection()

    df = pd.read_sql_query(
        sql,
        conn,
        params=params
    )

    conn.close()

    return df


def execute_query(sql, params=()):
    conn = get_connection()

    cur = conn.cursor()
    cur.execute(sql, params)

    conn.commit()

    last_id = cur.lastrowid

    conn.close()

    return last_id


# =========================================================
# DASHBOARD
# =========================================================

def dashboard():

    uid = current_user_id()

    sales = read_query(
        """
        SELECT COALESCE(SUM(total), 0) AS total
        FROM sales
        WHERE user_id = ?
        """,
        (uid,)
    )["total"].iloc[0]

    expenses = read_query(
        """
        SELECT COALESCE(SUM(amount), 0) AS total
        FROM expenses
        WHERE user_id = ?
        """,
        (uid,)
    )["total"].iloc[0]

    products = read_query(
        """
        SELECT *
        FROM products
        WHERE user_id = ?
        """,
        (uid,)
    )

    customers = read_query(
        """
        SELECT COUNT(*) AS total
        FROM customers
        WHERE user_id = ?
        """,
        (uid,)
    )["total"].iloc[0]

    profit = sales - expenses

    st.title("📊 Dashboard")

    st.caption(
        f"Welcome, {st.session_state.user_name}! "
        "Your business data is private to your account."
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "💰 Total Sales",
        f"₹{sales:,.2f}"
    )

    col2.metric(
        "💸 Expenses",
        f"₹{expenses:,.2f}"
    )

    col3.metric(
        "📈 Profit",
        f"₹{profit:,.2f}"
    )

    col4.metric(
        "👥 Customers",
        int(customers)
    )

    st.divider()

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("📦 Inventory")

        if products.empty:
            st.info("No products added yet.")

        else:

            total_stock = int(products["stock"].sum())

            low_stock = products[
                products["stock"] <= products["min_stock"]
            ]

            a, b = st.columns(2)

            a.metric(
                "Total Units",
                total_stock
            )

            b.metric(
                "Low Stock Items",
                len(low_stock)
            )

            if not low_stock.empty:

                st.warning("⚠️ Low stock")

                st.dataframe(
                    low_stock[
                        ["name", "stock", "min_stock"]
                    ],
                    use_container_width=True,
                    hide_index=True
                )

    with col2:

        st.subheader("🧾 Recent Sales")

        recent = read_query(
            """
            SELECT
                id,
                total,
                payment_method,
                sale_date
            FROM sales
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (uid,)
        )

        if recent.empty:
            st.info("No sales yet.")

        else:
            st.dataframe(
                recent,
                use_container_width=True,
                hide_index=True
            )


# =========================================================
# PRODUCTS
# =========================================================

def products_page():

    uid = current_user_id()

    st.title("📦 Products & Stock")

    add_tab, manage_tab = st.tabs(
        ["➕ Add Product", "📋 Manage Products"]
    )

    with add_tab:

        with st.form("add_product"):

            name = st.text_input("Product name")

            category = st.text_input("Category")

            price = st.number_input(
                "Selling price",
                min_value=0.0,
                step=1.0
            )

            stock = st.number_input(
                "Opening stock",
                min_value=0,
                step=1
            )

            min_stock = st.number_input(
                "Minimum stock alert",
                min_value=0,
                value=5,
                step=1
            )

            submitted = st.form_submit_button(
                "Add Product",
                type="primary"
            )

            if submitted:

                if not name:
                    st.error("Enter a product name.")

                else:

                    product_id = execute_query(
                        """
                        INSERT INTO products
                        (
                            user_id,
                            name,
                            category,
                            price,
                            stock,
                            min_stock,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uid,
                            name,
                            category,
                            price,
                            stock,
                            min_stock,
                            datetime.now().isoformat()
                        )
                    )

                    execute_query(
                        """
                        INSERT INTO stock_history
                        (
                            user_id,
                            product_id,
                            change_type,
                            quantity,
                            note,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uid,
                            product_id,
                            "Opening Stock",
                            stock,
                            "Initial stock",
                            datetime.now().isoformat()
                        )
                    )

                    st.success("Product added successfully!")

    with manage_tab:

        df = read_query(
            """
            SELECT
                id,
                name,
                category,
                price,
                stock,
                min_stock
            FROM products
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (uid,)
        )

        if df.empty:
            st.info("No products available.")

        else:

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

            st.divider()

            product_id = st.selectbox(
                "Select product",
                df["id"].tolist()
            )

            selected = df[
                df["id"] == product_id
            ].iloc[0]

            st.subheader("✏️ Edit Product")

            with st.form("edit_product"):

                new_name = st.text_input(
                    "Name",
                    value=selected["name"]
                )

                new_category = st.text_input(
                    "Category",
                    value=selected["category"] or ""
                )

                new_price = st.number_input(
                    "Price",
                    min_value=0.0,
                    value=float(selected["price"]),
                    step=1.0
                )

                new_min_stock = st.number_input(
                    "Minimum stock",
                    min_value=0,
                    value=int(selected["min_stock"]),
                    step=1
                )

                save = st.form_submit_button(
                    "Save Changes"
                )

                if save:

                    execute_query(
                        """
                        UPDATE products
                        SET
                            name = ?,
                            category = ?,
                            price = ?,
                            min_stock = ?
                        WHERE id = ?
                        AND user_id = ?
                        """,
                        (
                            new_name,
                            new_category,
                            new_price,
                            new_min_stock,
                            product_id,
                            uid
                        )
                    )

                    st.success("Product updated!")
                    st.rerun()

            st.divider()

            st.subheader("📦 Manage Stock")

            stock_change = st.number_input(
                "Quantity",
                min_value=1,
                step=1
            )

            change_type = st.selectbox(
                "Action",
                ["Add Stock", "Remove Stock"]
            )

            note = st.text_input(
                "Note"
            )

            if st.button(
                "Update Stock",
                type="primary"
            ):

                if change_type == "Add Stock":

                    execute_query(
                        """
                        UPDATE products
                        SET stock = stock + ?
                        WHERE id = ?
                        AND user_id = ?
                        """,
                        (
                            stock_change,
                            product_id,
                            uid
                        )
                    )

                    quantity = stock_change

                else:

                    if stock_change > int(selected["stock"]):
                        st.error("Not enough stock.")

                    else:

                        execute_query(
                            """
                            UPDATE products
                            SET stock = stock - ?
                            WHERE id = ?
                            AND user_id = ?
                            """,
                            (
                                stock_change,
                                product_id,
                                uid
                            )
                        )

                        quantity = -stock_change

                if change_type == "Add Stock" or stock_change <= int(selected["stock"]):

                    execute_query(
                        """
                        INSERT INTO stock_history
                        (
                            user_id,
                            product_id,
                            change_type,
                            quantity,
                            note,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uid,
                            product_id,
                            change_type,
                            quantity,
                            note,
                            datetime.now().isoformat()
                        )
                    )

                    st.success("Stock updated!")
                    st.rerun()


# =========================================================
# CUSTOMERS
# =========================================================

def customers_page():

    uid = current_user_id()

    st.title("👥 Customers")

    add_tab, manage_tab = st.tabs(
        ["➕ Add Customer", "📋 Customer List"]
    )

    with add_tab:

        with st.form("add_customer"):

            name = st.text_input("Customer name")
            phone = st.text_input("Phone")
            email = st.text_input("Email")
            address = st.text_area("Address")

            submitted = st.form_submit_button(
                "Add Customer",
                type="primary"
            )

            if submitted:

                if not name:
                    st.error("Enter customer name.")

                else:

                    execute_query(
                        """
                        INSERT INTO customers
                        (
                            user_id,
                            name,
                            phone,
                            email,
                            address,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uid,
                            name,
                            phone,
                            email,
                            address,
                            datetime.now().isoformat()
                        )
                    )

                    st.success("Customer added!")

    with manage_tab:

        df = read_query(
            """
            SELECT
                id,
                name,
                phone,
                email,
                address
            FROM customers
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (uid,)
        )

        if df.empty:
            st.info("No customers yet.")

        else:

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

            customer_id = st.selectbox(
                "Select customer",
                df["id"].tolist()
            )

            selected = df[
                df["id"] == customer_id
            ].iloc[0]

            st.subheader("✏️ Edit Customer")

            with st.form("edit_customer"):

                name = st.text_input(
                    "Name",
                    value=selected["name"]
                )

                phone = st.text_input(
                    "Phone",
                    value=selected["phone"] or ""
                )

                email = st.text_input(
                    "Email",
                    value=selected["email"] or ""
                )

                address = st.text_area(
                    "Address",
                    value=selected["address"] or ""
                )

                save = st.form_submit_button(
                    "Save Changes"
                )

                if save:

                    execute_query(
                        """
                        UPDATE customers
                        SET
                            name = ?,
                            phone = ?,
                            email = ?,
                            address = ?
                        WHERE id = ?
                        AND user_id = ?
                        """,
                        (
                            name,
                            phone,
                            email,
                            address,
                            customer_id,
                            uid
                        )
                    )

                    st.success("Customer updated!")
                    st.rerun()


# =========================================================
# SALES
# =========================================================

def sales_page():

    uid = current_user_id()

    st.title("💰 Sales")

    products = read_query(
        """
        SELECT id, name, price, stock
        FROM products
        WHERE user_id = ?
        ORDER BY name
        """,
        (uid,)
    )

    customers = read_query(
        """
        SELECT id, name
        FROM customers
        WHERE user_id = ?
        ORDER BY name
        """,
        (uid,)
    )

    if products.empty:
        st.warning("Add products before creating a sale.")
        return

    product_names = products["name"].tolist()

    selected_product_name = st.selectbox(
        "Product",
        product_names
    )

    product = products[
        products["name"] == selected_product_name
    ].iloc[0]

    st.write(
        f"Available stock: **{int(product['stock'])}**"
    )

    quantity = st.number_input(
        "Quantity",
        min_value=1,
        max_value=max(1, int(product["stock"])),
        value=1,
        step=1
    )

    unit_price = st.number_input(
        "Selling price",
        min_value=0.0,
        value=float(product["price"]),
        step=1.0
    )

    customer_options = ["Walk-in Customer"]

    customer_map = {}

    for _, row in customers.iterrows():
        label = f"{row['name']} — ID {row['id']}"
        customer_options.append(label)
        customer_map[label] = int(row["id"])

    customer_choice = st.selectbox(
        "Customer",
        customer_options
    )

    payment_method = st.selectbox(
        "Payment method",
        ["Cash", "UPI", "Card", "Bank Transfer", "Other"]
    )

    total = quantity * unit_price

    st.metric(
        "Total",
        f"₹{total:,.2f}"
    )

    if st.button(
        "Complete Sale",
        type="primary",
        use_container_width=True
    ):

        if quantity > int(product["stock"]):
            st.error("Not enough stock.")

        else:

            customer_id = customer_map.get(
                customer_choice
            )

            sale_id = execute_query(
                """
                INSERT INTO sales
                (
                    user_id,
                    customer_id,
                    total,
                    payment_method,
                    sale_date
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    uid,
                    customer_id,
                    total,
                    payment_method,
                    datetime.now().isoformat()
                )
            )

            execute_query(
                """
                INSERT INTO sale_items
                (
                    sale_id,
                    user_id,
                    product_id,
                    quantity,
                    price,
                    subtotal
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sale_id,
                    uid,
                    int(product["id"]),
                    quantity,
                    unit_price,
                    total
                )
            )

            execute_query(
                """
                UPDATE products
                SET stock = stock - ?
                WHERE id = ?
                AND user_id = ?
                """,
                (
                    quantity,
                    int(product["id"]),
                    uid
                )
            )

            execute_query(
                """
                INSERT INTO stock_history
                (
                    user_id,
                    product_id,
                    change_type,
                    quantity,
                    note,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    uid,
                    int(product["id"]),
                    "Sale",
                    -quantity,
                    f"Sale #{sale_id}",
                    datetime.now().isoformat()
                )
            )

            st.success(
                f"Sale #{sale_id} completed successfully!"
            )

    st.divider()

    st.subheader("📋 Sales History")

    history = read_query(
        """
        SELECT
            id AS Invoice,
            total AS Total,
            payment_method AS Payment,
            sale_date AS Date
        FROM sales
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (uid,)
    )

    if history.empty:
        st.info("No sales yet.")

    else:
        st.dataframe(
            history,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# EXPENSES
# =========================================================

def expenses_page():

    uid = current_user_id()

    st.title("💸 Expenses")

    with st.form("expense_form"):

        title = st.text_input(
            "Expense title"
        )

        category = st.selectbox(
            "Category",
            [
                "Rent",
                "Salary",
                "Transport",
                "Marketing",
                "Electricity",
                "Supplies",
                "Other"
            ]
        )

        amount = st.number_input(
            "Amount",
            min_value=0.0,
            step=1.0
        )

        expense_date = st.date_input(
            "Date",
            value=date.today()
        )

        notes = st.text_area(
            "Notes"
        )

        submit = st.form_submit_button(
            "Add Expense",
            type="primary"
        )

        if submit:

            if amount <= 0:
                st.error("Enter a valid amount.")

            else:

                execute_query(
                    """
                    INSERT INTO expenses
                    (
                        user_id,
                        title,
                        category,
                        amount,
                        expense_date,
                        notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uid,
                        title,
                        category,
                        amount,
                        str(expense_date),
                        notes
                    )
                )

                st.success("Expense added!")


    st.divider()

    df = read_query(
        """
        SELECT
            id,
            title,
            category,
            amount,
            expense_date,
            notes
        FROM expenses
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (uid,)
    )

    if df.empty:
        st.info("No expenses yet.")

    else:

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# STOCK HISTORY
# =========================================================

def stock_history_page():

    uid = current_user_id()

    st.title("📋 Stock History")

    df = read_query(
        """
        SELECT
            sh.id,
            p.name AS Product,
            sh.change_type AS Action,
            sh.quantity AS Quantity,
            sh.note AS Note,
            sh.created_at AS Date
        FROM stock_history sh
        JOIN products p
        ON p.id = sh.product_id
        WHERE sh.user_id = ?
        AND p.user_id = ?
        ORDER BY sh.id DESC
        """,
        (uid, uid)
    )

    if df.empty:
        st.info("No stock history yet.")

    else:

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True
        )


# =========================================================
# INVOICES
# =========================================================

def invoices_page():

    uid = current_user_id()

    st.title("🧾 Invoices")

    invoices = read_query(
        """
        SELECT
            s.id,
            s.total,
            s.payment_method,
            s.sale_date,
            COALESCE(c.name, 'Walk-in Customer') AS customer
        FROM sales s
        LEFT JOIN customers c
        ON s.customer_id = c.id
        WHERE s.user_id = ?
        ORDER BY s.id DESC
        """,
        (uid,)
    )

    if invoices.empty:
        st.info("No invoices available yet.")
        return

    st.dataframe(
        invoices,
        use_container_width=True,
        hide_index=True
    )

    invoice_id = st.selectbox(
        "Select invoice",
        invoices["id"].tolist()
    )

    invoice = invoices[
        invoices["id"] == invoice_id
    ].iloc[0]

    items = read_query(
        """
        SELECT
            p.name AS Product,
            si.quantity AS Quantity,
            si.price AS Price,
            si.subtotal AS Subtotal
        FROM sale_items si
        JOIN products p
        ON p.id = si.product_id
        WHERE si.sale_id = ?
        AND si.user_id = ?
        """,
        (
            invoice_id,
            uid
        )
    )

    st.divider()

    st.subheader(
        f"Invoice #{invoice_id}"
    )

    st.write(
        f"**Customer:** {invoice['customer']}"
    )

    st.write(
        f"**Date:** {invoice['sale_date']}"
    )

    st.write(
        f"**Payment:** {invoice['payment_method']}"
    )

    st.dataframe(
        items,
        use_container_width=True,
        hide_index=True
    )

    st.markdown(
        f"### Total: ₹{float(invoice['total']):,.2f}"
    )

    invoice_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Invoice #{invoice_id}</title>

        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
            }}

            h1 {{
                text-align: center;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}

            th, td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
            }}

            .total {{
                text-align: right;
                font-size: 20px;
                font-weight: bold;
                margin-top: 20px;
            }}
        </style>
    </head>

    <body>

        <h1>BUSINESS INVOICE</h1>

        <p>
            <strong>Invoice:</strong> #{invoice_id}
        </p>

        <p>
            <strong>Customer:</strong>
            {html.escape(str(invoice["customer"]))}
        </p>

        <p>
            <strong>Date:</strong>
            {html.escape(str(invoice["sale_date"]))}
        </p>

        <p>
            <strong>Payment:</strong>
            {html.escape(str(invoice["payment_method"]))}
        </p>

        {items.to_html(index=False)}

        <div class="total">
            Total: ₹{float(invoice["total"]):,.2f}
        </div>

    </body>
    </html>
    """

    st.download_button(
        "📥 Download Invoice",
        data=invoice_html,
        file_name=f"invoice_{invoice_id}.html",
        mime="text/html",
        use_container_width=True
    )


# =========================================================
# REPORTS
# =========================================================

def reports_page():

    uid = current_user_id()

    st.title("📈 Reports")

    sales = read_query(
        """
        SELECT
            DATE(sale_date) AS Date,
            SUM(total) AS Sales
        FROM sales
        WHERE user_id = ?
        GROUP BY DATE(sale_date)
        ORDER BY Date
        """,
        (uid,)
    )

    expenses = read_query(
        """
        SELECT
            expense_date AS Date,
            SUM(amount) AS Expenses
        FROM expenses
        WHERE user_id = ?
        GROUP BY expense_date
        ORDER BY Date
        """,
        (uid,)
    )

    if not sales.empty:

        st.subheader("💰 Daily Sales")

        st.line_chart(
            sales.set_index("Date")["Sales"]
        )

    else:
        st.info("No sales data available.")

    if not expenses.empty:

        st.subheader("💸 Daily Expenses")

        st.line_chart(
            expenses.set_index("Date")["Expenses"]
        )

    st.divider()

    st.subheader("📦 Inventory")

    inventory = read_query(
        """
        SELECT
            name,
            category,
            price,
            stock,
            (price * stock) AS Stock_Value
        FROM products
        WHERE user_id = ?
        ORDER BY name
        """,
        (uid,)
    )

    if not inventory.empty:

        st.dataframe(
            inventory,
            use_container_width=True,
            hide_index=True
        )

        csv = inventory.to_csv(index=False)

        st.download_button(
            "📥 Download Inventory CSV",
            csv,
            "inventory_report.csv",
            "text/csv"
        )


# =========================================================
# MAIN APPLICATION
# =========================================================

if not st.session_state.logged_in:

    show_authentication()

else:

    with st.sidebar:

        st.title("💼 Business Manager")

        st.success(
            f"Logged in as\n{st.session_state.user_name}"
        )

        page = st.radio(
            "Menu",
            [
                "📊 Dashboard",
                "📦 Products & Stock",
                "💰 Sales",
                "🧾 Invoices",
                "👥 Customers",
                "💸 Expenses",
                "📋 Stock History",
                "📈 Reports"
            ]
        )

        st.divider()

        if st.button(
            "🚪 Logout",
            use_container_width=True
        ):
            logout()

    if page == "📊 Dashboard":
        dashboard()

    elif page == "📦 Products & Stock":
        products_page()

    elif page == "💰 Sales":
        sales_page()

    elif page == "🧾 Invoices":
        invoices_page()

    elif page == "👥 Customers":
        customers_page()

    elif page == "💸 Expenses":
        expenses_page()

    elif page == "📋 Stock History":
        stock_history_page()

    elif page == "📈 Reports":
        reports_page()