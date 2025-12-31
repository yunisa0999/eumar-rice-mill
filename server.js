const express = require('express');
const session = require('express-session');
const path = require('path');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');
const app = express();
const PORT = 3000;

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'eumar_rice_mill',
});

 const USERS = {
  'erm@admin': { 
    password: '',  
    role: 'admin', 
    name: 'Admin User', 
    email: 'jonascylehr@gmail.com',
    resetToken: null,
    resetExpires: null
  },
  'staff': { 
    password: '',  
    role: 'staff', 
    name: 'Staff User',
    email: 'eunicemedalla87@gmail.com',
    resetToken: null,
    resetExpires: null
  },
};

 (async () => {
  USERS['erm@admin'].password = await bcrypt.hash('eumar@admin', 10);
  USERS['staff'].password = await bcrypt.hash('staff123', 10);
})();

 app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(session({
  secret: 'dev_secret_eumar',
  resave: false,
  saveUninitialized: false,
}));

 function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  if (req.session.user.role !== 'admin') return res.status(403).send('Access denied');
  next();
}

function requireStaff(req, res, next) {
  if (!req.session.user) return res.redirect('/');
  if (req.session.user.role !== 'staff') return res.status(403).send('Access denied');
  next();
}

 const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: 'eumarricemill@gmail.com',
    pass: 'olgvbmwtzxhzoauc',  
  },
  tls: { rejectUnauthorized: false },
});

 
 app.get('/', (req, res) => {
  if (req.session.user) {
    const role = req.session.user.role;
    if (role === 'admin') return res.redirect('/admin');
    if (role === 'staff') return res.redirect('/staff');
  }
  res.render('index', { user: null, error: null, success: null });
});

 app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('index', {
      user: null,
      error: 'Please enter both email and password.',
      success: null,
    });
  }

  const user = USERS[email];
  if (!user) {
    return res.render('index', {
      user: null,
      error: 'Invalid email or password.',
      success: null,
    });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.render('index', {
      user: null,
      error: 'Invalid email or password.',
      success: null,
    });
  }

  req.session.user = { email, name: user.name, role: user.role };
  res.render('index', { user, error: null, success: true });
});

 app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

 app.post('/forgot-password', async (req, res) => {
  const { emailOrUsername } = req.body;
  const user = USERS[emailOrUsername];

  if (!user) {
     return res.json({ success: true, message: 'If account exists, email sent.' });
  }

  const resetToken = crypto.randomBytes(20).toString('hex');
  const resetExpires = Date.now() + 3600000;  

  user.resetToken = resetToken;
  user.resetExpires = resetExpires;

  const resetLink = `http://localhost:${PORT}/reset-password/${resetToken}`;

  try {
    await transporter.sendMail({
      from: '"ERM System" <eumarricemill@gmail.com>',
      to: user.email,
      subject: 'ERM Password Reset',
      html: `
        <p>Hello ${user.name},</p>
        <p>Click the link below to reset your password:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>This link will expire in 1 hour.</p>
      `
    });

    res.json({ success: true, message: 'Reset email sent if account exists.' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Something went wrong.' });
  }
});

app.get('/reset-password/:token', (req, res) => {
  const { token } = req.params;
  const user = Object.values(USERS).find(u => u.resetToken === token && u.resetExpires > Date.now());
  if (!user) return res.send('Reset link is invalid or expired.');
  res.render('reset-password', { token });  
});


 app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const user = Object.values(USERS).find(u => u.resetToken === token && u.resetExpires > Date.now());
  if (!user) return res.send('Reset link is invalid or expired.');

  user.password = await bcrypt.hash(password, 10);  
  user.resetToken = null;
  user.resetExpires = null;

  res.send('Password updated successfully! You can now log in.');
});


app.get('/admin', requireLogin, async (req, res) => {
  try {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }

    const filter = req.query.filter || 'daily';

    const [totalSalesResult] = await pool.query(`
      SELECT COALESCE(SUM(total_amount), 0) AS total_sales 
      FROM sales 
      WHERE status = 'completed'
    `);
    const totalSales = totalSalesResult[0].total_sales;

    let salesFilterCondition = '';
    if (filter === 'daily') {
      salesFilterCondition = `DATE(created_at) = CURDATE()`;
    } else if (filter === 'monthly') {
      salesFilterCondition = `YEAR(created_at) = YEAR(CURDATE()) 
                              AND MONTH(created_at) = MONTH(CURDATE())`;
    } else if (filter === 'yearly') {
      salesFilterCondition = `YEAR(created_at) = YEAR(CURDATE())`;
    } else {
      salesFilterCondition = `DATE(created_at) = CURDATE()`;
    }

    const [filteredSalesResult] = await pool.query(`
      SELECT COALESCE(SUM(total_amount), 0) AS filtered_sales
      FROM sales
      WHERE status = 'completed' AND ${salesFilterCondition}
    `);
    const filteredSales = filteredSalesResult[0].filtered_sales;

    const [queueResult] = await pool.query(`
      SELECT COUNT(*) AS total_queue 
      FROM queue 
      WHERE status IN ('completed', 'done')
    `);
    const totalQueue = queueResult[0].total_queue;

    const [inventoryResult] = await pool.query(`
      SELECT COALESCE(SUM(quantity), 0) AS total_quantity 
      FROM inventory
    `);
    const totalInventory = inventoryResult[0].total_quantity;

    console.log('Admin Dashboard - totalInventory:', totalInventory);

    const [salesPie] = await pool.query(`
      SELECT status AS label, COUNT(*) AS value 
      FROM sales 
      GROUP BY status
    `);

    const [queuePie] = await pool.query(`
      SELECT 
        CASE 
          WHEN status IS NULL OR TRIM(status) = '' THEN 'cancelled'
          ELSE status
        END AS label,
        COUNT(*) AS value
      FROM queue
      GROUP BY label
    `);

    const [inventoryPie] = await pool.query(`
      SELECT category AS label, SUM(quantity) AS value 
      FROM inventory 
      GROUP BY category
    `);

    res.render('admin/admin-dashboard', {
      user: req.session.user,
      filter,
      totalSales,
      filteredSales,
      totalQueue,
      totalInventory,
      pieData: {
        sales: {
          labels: salesPie.map(r => r.label),
          data: salesPie.map(r => r.value)
        },
        queue: {
          labels: queuePie.map(r => r.label),
          data: queuePie.map(r => r.value)
        },
        inventory: {
          labels: inventoryPie.map(r => r.label),
          data: inventoryPie.map(r => r.value)
        }
      }
    });
  } catch (err) {
    console.error('❌ Error loading admin dashboard:', err);
    res.status(500).send('Server Error');
  }
});


async function logStaffAction(staff_email, action, details) {
  await pool.query(
    'INSERT INTO activity_logs (staff_email, action, details) VALUES (?, ?, ?)',
    [staff_email, action, details]
  );
}
app.get('/user-management', requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;

    const [logs] = await pool.query(
      `SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
      [limit, offset]
    );

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) as total FROM activity_logs`
    );

    const totalPages = Math.ceil(total / limit);

    res.render('admin/user-management', { logs, currentPage: page, totalPages });
  } catch (err) {
    console.error('Error fetching activity logs:', err);
    res.status(500).send('Internal Server Error');
  }
});



 async function calculateTotalAmount(itemId, quantity) {
  const [rows] = await pool.query(
    'SELECT unit_price, quantity AS stock, status FROM inventory WHERE item_id = ? LIMIT 1',
    [itemId]
  );

  if (rows.length === 0) {
    throw new Error('Product not found');
  }

  const item = rows[0];
  if (item.status !== 'in_stock') {
    throw new Error('Product is currently not in stock');
  }

  if (item.stock < quantity) {
    throw new Error(`Only ${item.stock} units available`);
  }

  const totalAmount = item.unit_price * quantity;
  return { unitPrice: item.unit_price, totalAmount };
}


app.post('/place-order', async (req, res) => {
  try {
    const { serviceType, name, product, quantity, amount } = req.body;

    if (!serviceType || !name) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }

    const quantityInt = quantity ? Number(quantity) : null;
    const amountFloat = amount ? Number(amount) : 0;

    const [maxResult] = await pool.query(`
      SELECT MAX(queue_number) AS maxQueue
      FROM queue
      WHERE DATE(created_at) = CURDATE()
    `);
    const nextQueueNumber = (maxResult[0].maxQueue || 0) + 1;

    let insertQuery = '';
    let values = [];

    if (serviceType === 'milling') {
      insertQuery = `
        INSERT INTO queue
        (customer_name, service_type, status, queue_number, created_at)
        VALUES (?, ?, 'waiting', ?, NOW())
      `;
      values = [name, serviceType, nextQueueNumber];

    } else if (serviceType === 'purchasing') {
      const productId = Number(product);
      if (!productId || isNaN(productId)) {
        return res.status(400).json({ error: 'Invalid product selected.' });
      }

      const { totalAmount } = await calculateTotalAmount(productId, quantityInt);

      insertQuery = `
        INSERT INTO queue
        (customer_name, service_type, product, quantity, amount, status, queue_number, created_at)
        VALUES (?, ?, ?, ?, ?, 'waiting', ?, NOW())
      `;
      values = [name, serviceType, productId, quantityInt, totalAmount, nextQueueNumber];

    } else {
      return res.status(400).json({ error: 'Invalid service type.' });
    }

    await pool.query(insertQuery, values);

    const [updatedQueue] = await pool.query(`
      SELECT *
      FROM queue
      ORDER BY queue_number ASC
    `);

    io.emit('queueUpdated', updatedQueue);

    res.json({ success: true, message: 'Order placed successfully' });

  } catch (error) {
    console.error('[PLACE ORDER ERROR]', error);
    res.status(500).json({ error: error.message || 'Failed to place order.' });
  }
});


app.get('/admin/inventory', requireAdmin, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 6;  
  const offset = (page - 1) * limit;

  try {
     const [statusRows] = await pool.query(`
      SELECT status, COUNT(*) AS total_items, SUM(quantity) AS total_quantity
      FROM inventory
      GROUP BY status
    `);

    let inStockCount = 0;
    let outOfStockCount = 0;
    let inStockQuantity = 0;
    let outOfStockQuantity = 0;

    statusRows.forEach(row => {
      if (row.status === 'in_stock') {
        inStockCount = row.total_items;
        inStockQuantity = row.total_quantity;
      } else if (row.status === 'out_of_stock') {
        outOfStockCount = row.total_items;
        outOfStockQuantity = row.total_quantity;
      }
    });

     const [inStockProducts] = await pool.query(`
      SELECT item_name, quantity, category
      FROM inventory
      WHERE status = 'in_stock'
      ORDER BY updated_at DESC
      LIMIT 10
    `);

     const [totalRows] = await pool.query('SELECT COUNT(*) AS total FROM inventory');
    const totalItems = totalRows[0].total;
    const totalPages = Math.ceil(totalItems / limit);

    const [rows] = await pool.query(
      'SELECT * FROM inventory ORDER BY item_id DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );

    const lowStockThreshold = 2;
    const lowStockItems = rows.filter(item => item.quantity <= lowStockThreshold);
    const lowStockAlert = lowStockItems.length > 0;

     res.render('admin/admin-inventory', {
      inventory: rows,
      currentPage: page,
      totalPages,
      lowStockAlert,
      inStockCount,
      outOfStockCount,
      inStockQuantity,
      outOfStockQuantity,
      inStockProducts
    });

  } catch (err) {
    console.error('Error retrieving inventory:', err);
    res.status(500).send('Error retrieving inventory data');
  }
});

app.get('/admin-products',  requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT status, COUNT(*) AS total_items, SUM(quantity) AS total_quantity
      FROM inventory
      GROUP BY status
    `);

    let inStockCount = 0;
    let outOfStockCount = 0;
    let inStockQuantity = 0;
    let outOfStockQuantity = 0;

    rows.forEach(row => {
      if (row.status === 'in_stock') {
        inStockCount = row.total_items;
        inStockQuantity = row.total_quantity;
      } else if (row.status === 'out_of_stock') {
        outOfStockCount = row.total_items;
        outOfStockQuantity = row.total_quantity;
      }
    });

    const [inStockProducts] = await pool.query(`
      SELECT item_name, quantity, category
      FROM inventory
      WHERE status = 'in_stock'
      ORDER BY updated_at DESC
      LIMIT 10
    `);

    res.render('admin/admin-products', {
      inStockCount,
      outOfStockCount,
      inStockQuantity,
      outOfStockQuantity,
      inStockProducts
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
});
app.post('/admin/product/add', requireAdmin, async (req, res) => {
  try {
    const { item_name, quantity, unit_price, category, status } = req.body;

    await pool.query(
      `INSERT INTO inventory (item_name, quantity, unit_price, category, status)
       VALUES (?, ?, ?, ?, ?)`,
      [item_name, quantity, unit_price, category, status]
    );

    res.redirect('/admin/inventory?success=1');  
  } catch (err) {
    console.error('Error adding product:', err);
    res.redirect('/admin/inventory?error=1');    
  }
});



app.post('/inventory/edit/:id',  requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { item_name, quantity, unit_price, category } = req.body; 
  try {
    await pool.query(
      `UPDATE inventory 
       SET item_name = ?, quantity = ?, unit_price = ?, category = ? 
       WHERE item_id = ?`, 
      [item_name, quantity, unit_price, category, id]
    );
    res.redirect('/admin/inventory');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Error updating product');
  }
});

app.get('/inventory/delete/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM inventory WHERE item_id = ?', [id]);
    res.redirect('/admin/inventory');  
  } catch (err) {
    console.error(err);
    return res.status(500).send('Error deleting product');
  }
});
app.get('/inventory/search', async (req, res) => {
  const query = req.query.query;

  try {
     const [results] = await pool.query(
      'SELECT * FROM inventory WHERE LOWER(item_name) LIKE LOWER(?)',
      [`%${query}%`]
    );

     const [[inStockCount]] = await pool.query(
      "SELECT COUNT(*) AS count FROM inventory WHERE status = 'in_stock'"
    );

     const [[outOfStockCount]] = await pool.query(
      "SELECT COUNT(*) AS count FROM inventory WHERE status = 'out_of_stock'"
    );

     const [[inStockQuantity]] = await pool.query(
      "SELECT SUM(quantity) AS quantity FROM inventory WHERE status = 'in_stock'"
    );

    const [[outOfStockQuantity]] = await pool.query(
      "SELECT SUM(quantity) AS quantity FROM inventory WHERE status = 'out_of_stock'"
    );

     const [inStockProducts] = await pool.query(
      "SELECT item_name, quantity FROM inventory WHERE status = 'in_stock' LIMIT 10"
    );

     res.render("admin/admin-inventory", {
      inventory: results,
      query: query,
      currentPage: 1,
      totalPages: 1,

       inStockCount: inStockCount.count || 0,
      outOfStockCount: outOfStockCount.count || 0,
      inStockQuantity: inStockQuantity.quantity || 0,
      outOfStockQuantity: outOfStockQuantity.quantity || 0,
      inStockProducts: inStockProducts || []
    });

  } catch (err) {
    console.error("Search error:", err);
    res.status(500).send("Server error");
  }
});

app.post('/inventory/update-stock/:item_id', async (req, res) => {
  const itemId = req.params.item_id;
  const { status } = req.body;  

  if (status !== 'in_stock' && status !== 'out_of_stock') {
    return res.status(400).send('Invalid stock status');
  }

  try {
    await pool.query('UPDATE inventory SET status = ? WHERE item_id = ?', [status, itemId]);
    res.redirect('/admin/inventory');  
  } catch (err) {
    console.error('Error updating stock status:', err);
    return res.status(500).send('Error updating stock status');
  }
});

const groupBy = (array, keyFn) => {
  return array.reduce((acc, item) => {
    const key = keyFn(item);
    if (!acc[key]) acc[key] = [];
    acc[key].push(item);
    return acc;
  }, {});
};

app.get('/admin/queue', requireAdmin, async (req, res) => {
  try {

     const [queueList] = await pool.query(`
      SELECT 
        queue_id AS id, 
        customer_name AS customerName, 
        status, 
        created_at
      FROM queue
      ORDER BY created_at DESC
    `);

     const analytics = {
      waitingCount: 0,
      servingCount: 0,
      cancelledCount: 0,
      doneCount: 0,
    };

    queueList.forEach(item => {
      const status = item.status ? item.status.toLowerCase() : '';
      if (status === 'waiting') analytics.waitingCount++;
      else if (status === 'serving') analytics.servingCount++;
      else if (status === 'cancelled' || status === 'rejected') analytics.cancelledCount++;
      else if (status === 'completed' || status === 'done') analytics.doneCount++;
    });

     const purchaseSQL = `
      SELECT 
        q.queue_id,
        q.customer_name,
        q.service_type,
        q.sacks,
        q.weight,
        q.product AS queue_product,
        q.quantity AS queue_quantity,
        q.queue_number,
        q.status AS queue_status,
        q.created_at AS queue_created_at,

        s.sale_id,
        s.product_id,
        s.total_amount,
        s.quantity AS sale_quantity,
        s.price_per_unit,
        s.created_at AS sale_created_at,

        p.name AS product_name,
        p.description AS product_description
      FROM queue q
      LEFT JOIN sales s ON q.queue_id = s.queue_id
      LEFT JOIN products p ON s.product_id = p.id
      ORDER BY q.created_at DESC, sale_created_at DESC
    `;

    const [purchases] = await pool.query(purchaseSQL);

     purchases.forEach(row => {
      row.queue_created_at_formatted = row.queue_created_at 
        ? new Date(row.queue_created_at).toLocaleString('en-US', { 
            year:'numeric', month:'2-digit', day:'2-digit',
            hour:'2-digit', minute:'2-digit', hour12:true 
          })
        : '-';

      row.sale_created_at_formatted = row.sale_created_at 
        ? new Date(row.sale_created_at).toLocaleString('en-US', { 
            year:'numeric', month:'2-digit', day:'2-digit',
            hour:'2-digit', minute:'2-digit', hour12:true 
          })
        : '-';

      row.queue_quantity = row.queue_quantity ?? null;
      row.weight = row.weight ?? null;
      row.sacks = row.sacks ?? null;
      row.total_amount = row.total_amount ?? null;
    });

     res.render('admin/admin-queue', {
      user: req.session.user,
      queueList,
      analytics,
      purchases
    });

  } catch (err) {
    console.error('Error loading queue page:', err);
    res.status(500).send('Server Error');
  }
});


app.get('/admin/sales', async (req, res) => {
  const { startDate, endDate } = req.query;
  const params = [];

  let salesSql = `
    SELECT 
      s.sale_id, 
      s.queue_id, 
      q.customer_name, 
      s.product_id, 
      p.name AS product_name,
      s.quantity, 
      s.price_per_unit, 
      s.total_amount, 
      s.payment_method,
      s.status, 
      s.created_at
    FROM sales s
    LEFT JOIN queue q ON s.queue_id = q.queue_id
    LEFT JOIN products p ON s.product_id = p.id
    WHERE s.status = 'completed'
  `;

  if (startDate && endDate) {
    salesSql += ` AND DATE(s.created_at) BETWEEN ? AND ?`;
    params.push(startDate, endDate);
  }

  salesSql += ` ORDER BY s.created_at DESC;`;

  try {
    const [salesResults] = await pool.query(salesSql, params);

    let salesTotalsSql = `
      SELECT 
        COUNT(*) AS totalTransactions,
        COALESCE(SUM(total_amount), 0) AS totalRevenue
      FROM sales
      WHERE status = 'completed'
    `;
    const salesTotalsParams = [];
    if (startDate && endDate) {
      salesTotalsSql += ` AND DATE(created_at) BETWEEN ? AND ?`;
      salesTotalsParams.push(startDate, endDate);
    }

    const [salesTotals] = await pool.query(salesTotalsSql, salesTotalsParams);
    const totalTransactions = salesTotals[0]?.totalTransactions || 0;
    const totalRevenue = salesTotals[0]?.totalRevenue || 0;

    const groupedByDate = groupBy(salesResults, (r) => {
      const date = new Date(r.created_at);
      return date.toISOString().split('T')[0];
    });

    const chartLabels = Object.keys(groupedByDate).sort();
    const chartRevenueData = chartLabels.map(date => 
      groupedByDate[date].reduce((sum, sale) => sum + parseFloat(sale.total_amount || 0), 0)
    );
    const chartSalesData = chartLabels.map(date => 
      groupedByDate[date].reduce((sum, sale) => sum + parseInt(sale.quantity || 0), 0)
    );

    res.render('admin/admin-sales', {
      sales: salesResults,
      totalTransactions,
      totalRevenue,
      chartLabels,
      chartRevenueData,
      chartSalesData,
      filtered: !!(startDate && endDate),
      startDate,
      endDate
    });

  } catch (err) {
    console.error('Error fetching sales:', err);
    res.status(500).send('Database error');
  }
});

app.post('/admin/sales/filter', async (req, res) => {
    const { startDate, endDate } = req.body;

    try {
        const [results] = await pool.query(`
            SELECT 
                s.sale_id,
                s.created_at,
                s.total_amount,
                s.quantity,
                s.price_per_unit,
                s.payment_method,
                s.status,
                c.name AS customer_name,
                p.name AS product_name
            FROM sales s
            LEFT JOIN queue q ON s.queue_id = q.queue_id
            LEFT JOIN customers c ON q.customer_name = c.name
            LEFT JOIN products p ON s.product_id = p.id
            WHERE DATE(s.created_at) BETWEEN ? AND ?
            ORDER BY s.created_at DESC
        `, [startDate, endDate]);

        const totalSales = results.length;
        const totalRevenue = results.reduce((sum, row) => sum + parseFloat(row.total_amount || 0), 0);

        res.render('admin/admin-sales', {
            sales: results,
            totalSales,
            totalRevenue,
            filtered: true,
            startDate,
            endDate
        });
    } catch (err) {
        console.error('Error filtering sales:', err);
        res.status(500).send('Error filtering sales');
    }
});

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  next();
}

app.post('/customer/manual-milling', async (req, res) => {
  try {
    const { customer_name, contact_number } = req.body;

    if (!customer_name || !contact_number) {
      return res.status(400).json({ message: 'Missing fields' });
    }

     const [lastQueue] = await pool.query(
      'SELECT queue_number FROM queue WHERE service_type = ? ORDER BY queue_number DESC LIMIT 1',
      ['milling']
    );
    const nextQueueNumber = (lastQueue[0]?.queue_number || 0) + 1;

     await pool.query(
      `INSERT INTO queue (customer_name, contact_number, service_type, status, queue_number, created_at)
       VALUES (?, ?, 'milling', 'waiting', ?, NOW())`,
      [customer_name, contact_number, nextQueueNumber]
    );

     res.json({ success: true, message: 'Manual milling added successfully!' });

  } catch (error) {
    console.error('❌ Error inserting manual milling:', error);
    res.status(500).json({ message: 'Database error', error: error.message });
  }
});


app.get('/customer', async (req, res) => {
  try {
    const action = req.query.action;

    const [allQueues] = await pool.query(
      'SELECT queue_number, customer_name, service_type, status, created_at FROM queue ORDER BY created_at ASC'
    );

    res.render('customer/customer-dashboard', {
      user: null,
      allQueues,
      action
    });
  } catch (error) {
    console.error('Database query error:', error);
    res.render('customer/customer-dashboard', {
      user: null,
      allQueues: [],
      action: null
    });
  }
});

app.get(['/overview', '/staff-overview'], async (req, res) => {
  try {

    const [salesToday] = await pool.query(`
      SELECT COUNT(*) AS totalSalesCountToday, 
             COALESCE(SUM(total_amount), 0) AS totalRevenueToday 
      FROM sales 
      WHERE DATE(created_at) = CURDATE()
    `);

    const [orderStats] = await pool.query(`
      SELECT 
        SUM(status IN ('waiting', 'serving')) AS pendingOrders,
        SUM(status = 'done') AS completedOrders
      FROM queue
    `);

    const [queueData] = await pool.query(`
      SELECT 
        COUNT(*) AS activeCustomers,
        AVG(wait_time) AS avgWaitTime,
        SUM(status = 'serving') AS currentlyServing,
        SUM(status = 'waiting') AS inQueue
      FROM queue
      WHERE status IN ('waiting', 'serving')
    `);

    const [nextInQueue] = await pool.query(`
      SELECT customer_name 
      FROM queue 
      WHERE status = 'waiting' 
      ORDER BY created_at ASC 
      LIMIT 1
    `);
  
    const [outOfStockItems] = await pool.query(`
      SELECT item_name, quantity
      FROM inventory
      WHERE quantity = 0
    `);

    const [salesByDate] = await pool.query(`
      SELECT DATE(created_at) as date, SUM(total_amount) as total
      FROM sales
      WHERE created_at >= CURDATE() - INTERVAL 6 DAY
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `);

    const salesChartData = {};
    const today = new Date();
    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      const key = d.toISOString().split('T')[0];
      salesChartData[key] = 0;
    }
    salesByDate.forEach(sale => {
      const date = new Date(sale.date).toISOString().split('T')[0];
      salesChartData[date] = parseFloat(sale.total);
    });

    res.render('staff/staff-overview', {
      totalSalesCount: salesToday[0].totalSalesCountToday || 0,
      totalRevenue: Number(salesToday[0].totalRevenueToday) || 0,
      pendingOrders: orderStats[0].pendingOrders || 0,
      completedOrders: orderStats[0].completedOrders || 0,
      activeCustomers: queueData[0].activeCustomers || 0,
      avgWaitTime: Math.round(queueData[0].avgWaitTime) || 0,
      currentlyServing: queueData[0].currentlyServing || 0,
      inQueue: queueData[0].inQueue || 0,
      nextInQueue: nextInQueue[0]?.customer_name || null,
      
      outOfStockItems,   
      
      salesByDate: salesChartData
    });

  } catch (error) {
    console.error('Error loading overview:', error);
    res.status(500).send('Server Error');
  }
});


app.post('/staff/queue/next', async (req, res) => {
  const { queueId } = req.body;

  if (!queueId) return res.status(400).send('Missing queue ID');

  try {
   await pool.query(`
  UPDATE queue 
  SET status = 'serving' 
  WHERE queue_id = ?
`, [queueId]);


    res.redirect('/staff/dashboard');
  } catch (err) {
    console.error('[QUEUE UPDATE ERROR]', err);
    res.status(500).send('Failed to update queue status');
  }
});

 
app.get('/staff-inventory', async (req, res) => {
  try {
    const [items] = await pool.query('SELECT * FROM inventory');
    res.render('staff/staff-inventory', { items });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


app.post('/staff/inventory/add', requireStaff, async (req, res) => {
  try {
    const { item_name, quantity, unit_price, category } = req.body;

    const quantityNum = parseInt(quantity);
    const unitPriceNum = parseFloat(unit_price);

    const status = quantityNum > 0 ? 'in_stock' : 'out_of_stock';

     const [result] = await pool.query(
      `INSERT INTO inventory (item_name, quantity, unit_price, category, status, updated_at)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [item_name, quantityNum, unitPriceNum, category, status]
    );

     await logStaffAction(
      req.session.user.email,
      'Added new inventory item',
      `Item: ${item_name}, Quantity: ${quantityNum}, Unit Price: ₱${unitPriceNum.toFixed(2)}, Category: ${category}, Status: ${status}`
    );

    res.redirect('/staff-inventory');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


app.get('/sales', (req, res) => {
  res.render('staff/staff-sales-insight');
});

app.get('/api/staff/sales-insight', async (req, res) => {
  try {
    const [totalSalesRows] = await pool.query(`
      SELECT IFNULL(SUM(total_amount), 0) AS total_sales
      FROM sales
      WHERE status = 'completed'
    `);
    const totalSales = totalSalesRows[0].total_sales;

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const offset = (page - 1) * limit;

    const [recentSalesRows] = await pool.query(`
      SELECT 
        s.sale_id, 
        p.name AS product_name, 
        s.customer_name, 
        s.quantity,
        s.total_amount, 
        s.created_at
      FROM sales s
      LEFT JOIN products p ON s.product_id = p.id
      WHERE s.status = 'completed'
      ORDER BY s.created_at DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    res.json({
      totalSales,
      recentTransactions: recentSalesRows
    });

  } catch (error) {
    console.error('❌ Error fetching sales insight:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/complete-milling', async (req, res) => {
  const { queueId, amount } = req.body;

  if (!queueId || !amount) {
    return res.status(400).json({ error: 'Queue ID and amount are required.' });
  }

  try {
    await pool.query(
      `UPDATE queue SET status = 'completed', amount = ? WHERE id = ? AND service_type = 'milling'`,
      [amount, queueId]
    );

    await pool.query(
      `INSERT INTO sales (customer_name, service_type, total_amount, created_at, status)
       SELECT customer_name, 'milling', ?, NOW(), 'completed' 
       FROM queue WHERE id = ?`,
      [amount, queueId]
    );

    res.json({ success: true, message: 'Milling completed and recorded in sales.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to complete milling.' });
  }
});
app.get('/api/daily-sales', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT DATE(created_at) AS date, SUM(total_amount) AS amount
      FROM sales
      WHERE status = 'completed'
      GROUP BY DATE(created_at)
      ORDER BY DATE(created_at)
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch daily sales' });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const [products] = await pool.query(`
      SELECT item_id AS id, item_name AS name, unit_price AS price, quantity
      FROM inventory
      WHERE status = 'in_stock' AND quantity > 0
      ORDER BY item_name ASC
    `);
    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Failed to load products' });
  }
});

app.post('/api/manual-order', async (req, res) => {
  try {
    const { customerName, productId, quantity } = req.body;

    if (!customerName || !productId || !quantity) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

     const [rows] = await pool.query('SELECT * FROM products WHERE id = ?', [productId]);
    if (rows.length === 0) {
      return res.status(400).json({ message: 'Selected product does not exist.' });
    }

    const product = rows[0];
    const amount = Number(product.price) * Number(quantity);

     await pool.query(
      `INSERT INTO queue
       (customer_name, product_id, product, quantity, amount, status, created_at, service_type)
       VALUES (?, ?, ?, ?, ?, 'waiting', NOW(), 'purchasing')`,
      [customerName, productId, product.name, quantity, amount]
    );

    res.json({ message: 'Manual order submitted successfully' });

  } catch (err) {
    console.error('Error inserting manual order:', err);
    res.status(500).json({ message: 'Failed to submit manual order.' });
  }
});


 app.post('/queue/:id/input-amount', requireStaff, async (req, res) => {
  const queueId = req.params.id;
  const amount = parseFloat(req.body.amount);
  const weight = parseFloat(req.body.weight);
  const quantity = parseInt(req.body.quantity, 10);

  if (isNaN(amount) || amount < 0) return res.status(400).send('Invalid amount');
  if (isNaN(weight) || weight < 0) return res.status(400).send('Invalid weight');
  if (isNaN(quantity) || quantity < 0) return res.status(400).send('Invalid quantity');

  try {
    const [result] = await pool.query(
      'UPDATE queue SET amount = ?, weight = ?, quantity = ? WHERE queue_id = ?',
      [amount, weight, quantity, queueId]
    );

    if (result.affectedRows === 0) return res.status(404).send('Queue item not found');

    await logStaffAction(
      req.session.user.email,
      'Updated queue details',
      `Queue ID: ${queueId}, Amount: ₱${amount.toFixed(2)}, Weight: ${weight}kg, Quantity: ${quantity} sacks`
    );

    await emitQueueUpdate();  

    res.redirect('/queue');
  } catch (err) {
    console.error('Error updating queue details:', err);
    res.status(500).send('Server error');
  }
}); 
async function getAllQueueData() {
  const [waitingServingRows] = await pool.query(`
    SELECT q.queue_id AS id,
           q.customer_name,
           q.service_type,
           q.status,
           q.queue_number,
           q.quantity,
           q.amount,
           q.contact_number,
           q.service_requested,
           q.notes,
           q.sacks,
           q.product_type,
           i.item_name AS product_name
    FROM queue q
    LEFT JOIN inventory i ON q.product = i.item_id
    WHERE q.status IN ('waiting', 'serving')
    ORDER BY q.created_at ASC
  `);

  const [completedRows] = await pool.query(`
    SELECT q.queue_id AS id,
           q.customer_name,
           q.service_type,
           q.status,
           q.queue_number,
           q.quantity,
           q.amount,
           q.contact_number,
           q.service_requested,
           q.notes,
           q.sacks,
           q.product_type,
           i.item_name AS product_name
    FROM queue q
    LEFT JOIN inventory i ON q.product = i.item_id
    WHERE q.status = 'completed'
    ORDER BY q.created_at ASC
  `);

  const [cancelledRows] = await pool.query(`
    SELECT q.queue_id AS id,
           q.customer_name,
           q.service_type,
           q.status,
           q.queue_number,
           q.quantity,
           q.amount,
           q.contact_number,
           q.service_requested,
           q.notes,
           q.sacks,
           q.product_type,
           i.item_name AS product_name
    FROM queue q
    LEFT JOIN inventory i ON q.product = i.item_id
    WHERE q.status = 'cancelled'
    ORDER BY q.created_at ASC
  `);

  return { waitingServingRows, completedRows, cancelledRows };
}
 
async function emitQueueUpdate() {
  try {
    const { waitingServingRows } = await getAllQueueData();
    io.emit('queueUpdated', waitingServingRows); // 🔔 Broadcast live updates
  } catch (error) {
    console.error('Error emitting queue update:', error);
  }
}

app.get(['/queue', '/staff'], async (req, res) => {
  const action = req.query.action || null;
  const { waitingServingRows, completedRows, cancelledRows } = await getAllQueueData();

  res.render('staff/staff-dashboard', {
    user: req.session.user || { username: 'Staff' },
    queueDetails: waitingServingRows,
    completedQueues: completedRows,
    cancelledQueues: cancelledRows,
    action
  });
}); 
app.get('/queue/:id/details', requireStaff, async (req, res) => {
  const queueId = req.params.id;

  try {
    const [rows] = await pool.query(`
      SELECT 
        q.queue_id AS id,
        q.customer_name,
        q.contact_number,
        q.service_type,
        q.status,
        q.queue_number,
        q.quantity,
        q.amount,
        q.notes,
        q.sacks,
        q.product_type,
        q.weight,
        q.service_requested,
        i.item_name AS product_name,
        i.unit_price AS product_price
      FROM queue q
      LEFT JOIN inventory i ON q.product = i.item_id
      WHERE q.queue_id = ?
      LIMIT 1
    `, [queueId]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Queue record not found' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching queue details:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
 
app.get('/api/sales-summary', requireStaff, async (req, res) => {
  try { 
    const [rows] = await pool.query(`
      SELECT DATE_FORMAT(created_at, '%Y-%m') AS label, SUM(total_amount) AS amount
      FROM sales
      WHERE status = 'completed'
      GROUP BY label
      ORDER BY label ASC
    `);

    res.json(rows.map(r => ({ label: r.label, amount: parseFloat(r.amount) })));
  } catch (err) {
    console.error('Failed to fetch sales summary:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

 
app.post('/queue/:id/done', requireStaff, async (req, res) => {
  const queueId = req.params.id;

  try { 
    const [queueRows] = await pool.query(
      `SELECT q.*, i.item_name AS product_name, i.unit_price AS product_price, i.quantity AS inventory_qty
       FROM queue q
       LEFT JOIN inventory i ON q.product = i.item_id
       WHERE q.queue_id = ? LIMIT 1`,
      [queueId]
    );

    if (queueRows.length === 0) return res.status(404).send('Queue item not found');

    const item = queueRows[0];

    let amount = Number(item.amount) || 0;  
    let pricePerUnit = 0;
    const productId = item.product || null;

     if (item.service_type === 'purchasing') {
      if (!productId || item.quantity <= 0) 
        return res.status(400).send('Product and quantity required for purchasing');

      const purchaseQty = Number(item.quantity);
      pricePerUnit = Number(item.product_price || 0);

      if (amount <= 0) {
        amount = purchaseQty * pricePerUnit;
      }

      if (item.inventory_qty < purchaseQty) {
        return res.status(400).send(`Insufficient inventory for "${item.product_name}"`);
      }
    }

     else if (item.service_type === 'milling') {
     }

     await pool.query(
      `INSERT INTO sales (
        queue_id,
        service_type,
        product_id,
        total_amount,
        payment_method,
        status,
        quantity,
        price_per_unit,
        customer_name,
        created_at
      ) VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?, NOW())`,
      [
        item.queue_id,
        item.service_type,
        productId,
        amount,
        item.payment_method || 'cash',
        Number(item.quantity) || 1,
        pricePerUnit,
        item.customer_name
      ]
    );

     if (item.service_type === 'purchasing') {
      const newQty = item.inventory_qty - Number(item.quantity);
      await pool.query(
        `UPDATE inventory
         SET quantity = ?, status = CASE WHEN ? <= 0 THEN 'out_of_stock' ELSE 'in_stock' END
         WHERE item_id = ?`,
        [newQty, newQty, productId]
      );
    }

     await pool.query(
      `UPDATE queue SET status = ?, amount = ? WHERE queue_id = ?`,
      ['completed', amount, queueId]
    );

    await logStaffAction(
      req.session.user.email,
      'Completed queue item',
      `Queue ID: ${queueId}, Customer: ${item.customer_name}, Service: ${item.service_type}, Amount: ₱${amount.toFixed(2)}`
    );

    await emitQueueUpdate();

    res.redirect('/queue?action=done');
  } catch (err) {
    console.error('Error completing queue:', err);
    res.status(500).send('Server error');
  }
});


app.post('/queue/:id/cancel', requireStaff, async (req, res) => {
  const queueId = req.params.id;

  try {
     const [result] = await pool.query(
      'UPDATE queue SET status = ? WHERE queue_id = ? AND status NOT IN ("completed")',
      ['cancelled', queueId]
    );

    if (result.affectedRows === 0) {
      return res.status(400).send('Cannot cancel a completed queue');
    }

    if (req.session.user && req.session.user.email) {
      await logStaffAction(
        req.session.user.email,
        'Cancelled queue request',
        `Queue ID: ${queueId}`
      );
    }
  await emitQueueUpdate();
    res.redirect('/staff?action=cancelled');
  } catch (err) {
    console.error('Error cancelling queue:', err);
    res.status(500).send('Server error');
  }
});
app.post('/queue/:queueId/approve', requireStaff, async (req, res) => {
  const queueId = req.params.queueId;
  try {
    await pool.query(
      'UPDATE queue SET status = ? WHERE queue_id = ?',
      ['serving', queueId]
    );

    await logStaffAction(
      req.session.user.email,
      'Approved queue request',
      `Queue ID: ${queueId}`
    );

     await emitQueueUpdate();

     io.to(`queue-${queueId}`).emit('queueApproved', {
      message: 'Your order has been approved! Please proceed to the counter.',
      queueId
    });

    res.redirect('/staff?action=approved');
  } catch (error) {
    console.error('Error approving queue:', error);
    res.status(500).send('Server error');
  }
});


 
app.get('/queue/completed', async (req, res) => {
  try {
    const [doneQueues] = await pool.query(
      `SELECT queue_id AS id, customer_name, service_type, status, queue_number
       FROM queue
       WHERE status = 'completed'
       ORDER BY created_at DESC`
    );

    res.render('staff/staff-queue-completed', { doneQueues });
  } catch (error) {
    console.error('Error fetching completed queue:', error);
    res.status(500).send('Server Error');
  }
});
 app.post('/queue/:id/complete', requireStaff, async (req, res) => {
  const queueId = req.params.id;
  try {
     const [rows] = await pool.query('SELECT * FROM queue WHERE queue_id = ?', [queueId]);
    if(!rows.length) return res.status(404).send('Queue not found');
    const queue = rows[0];

     await pool.query(`
      INSERT INTO sales (queue_id, service_type, total_amount, status, created_at)
      VALUES (?, ?, ?, 'completed', NOW())
    `, [queueId, queue.service_type, queue.amount || 0]);

     await pool.query('UPDATE queue SET status = ? WHERE queue_id = ?', ['completed', queueId]);

    res.send('Queue completed and sales recorded.');
  } catch(err) {
    console.error('Error completing queue:', err);
    res.status(500).send('Server error');
  }
});




function capitalize(str) {
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : '';
}

const PDFDocument = require('pdfkit');
const fs = require('fs');

app.get('/generate-ticket/:queueId', async (req, res) => {
  const queueId = req.params.queueId;

  try {
    const [rows] = await pool.query(`
      SELECT q.*, i.item_name AS product_name
      FROM queue q
      LEFT JOIN inventory i ON q.product = i.item_id
      WHERE q.queue_id = ?
    `, [queueId]);

    if (!rows.length) return res.status(404).send('Queue ticket not found');

    const ticket = rows[0];

    const amount = Number(ticket.amount) || 0;
    const weight = Number(ticket.weight) || 0;
    const quantity = Number(ticket.quantity) || 0;

    const doc = new PDFDocument({ size: [300, 600], margin: 20 });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=ticket-${ticket.queue_id}.pdf`
    );

    doc.pipe(res);

    const logoPath = path.join(__dirname, "public", "erm.jpg");

    if (fs.existsSync(logoPath)) {
      doc.image(logoPath, {
        fit: [70, 70],
        align: 'center'
      });
      doc.moveDown(1.5);
    } else {
      console.log("⚠ Logo NOT found at:", logoPath);
    }

    doc.font("Helvetica-Bold")
       .fontSize(18)
       .text("EUMAR RICE MILL", { align: "center" });
    doc.moveDown();

    doc.font("Helvetica").fontSize(12);
    doc.text(`Queue ID: ${ticket.queue_id}`);
    doc.text(`Customer: ${ticket.customer_name}`);
    doc.text(`Service: ${ticket.service_type}`);
    doc.text(`Queue #: ${ticket.queue_number}`);
    doc.moveDown();

     if (ticket.service_type.toLowerCase() === "milling") {
      doc.text(`Weight: ${weight} kg`);
      doc.text(`Sacks: ${quantity}`);
      doc.text(`Amount: ${amount.toFixed(2)}`);
    }

    if (ticket.service_type.toLowerCase() === "purchasing") {
      doc.text(`Product: ${ticket.product_name || "N/A"}`);
      doc.text(`Quantity: ${quantity}`);
      doc.text(`Amount: ${amount.toFixed(2)}`);
      doc.text(`Notes: ${ticket.notes || "None"}`);
    }

    doc.moveDown(2);
    doc.text("Thank you!", { align: "center" });

    doc.end();

  } catch (err) {
    console.error("Error generating ticket:", err);
    if (!res.headersSent) res.status(500).send("Server error generating ticket");
  }
});


app.get('/join-queue', (req, res) => {
  res.render('customer/join-queue');
});

const server = app.listen(PORT, () => {
  console.log(`Eumar Rice Mill app running at http://localhost:${PORT}`);
});

const io = new Server(server); 

io.on('connection', (socket) => {
  console.log('🟢 Staff connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('🔴 Staff disconnected:', socket.id);
  });
});
