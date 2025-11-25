const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Razorpay = require('razorpay');
const cloudinary = require('cloudinary').v2;
const uuidv4 = require('uuid').v4;
const multer = require('multer');

dotenv.config();

const app = express();

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : '*',
  credentials: true
}));
app.use(express.json());

// Cloudinary Config
cloudinary.config({
  cloud_name: 'dwvx9kg8e',
  api_key: '454177812827398',
  api_secret: 'nUJL9QABXjQgmbMyKTId_laog74'
});

// Multer Config (Memory storage for serverless file uploads)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Razorpay Config
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || '',
  key_secret: process.env.RAZORPAY_KEY_SECRET || ''
});

// Constants
const SECRET_KEY = process.env.JWT_SECRET_KEY || 'your-secret-key-change-in-production';
const ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7; // 7 days

// --- Database Connection (Cached for Serverless) ---
let isConnected = false;
const connectDB = async () => {
  if (isConnected) return;
  try {
    await mongoose.connect(process.env.MONGO_URL, { dbName: process.env.DB_NAME });
    isConnected = true;
    console.log("Connected to MongoDB");
  } catch (err) {
    console.error("MongoDB connection error:", err);
  }
};

// --- Mongoose Schemas ---
const userSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String }, // Optional for Clerk users
  name: { type: String, required: true },
  role: { type: String, default: 'user' },
  clerk_id: { type: String },
  profile_image_url: { type: String },
  purchased_products: [{ type: String }], // Stores Product IDs
  created_at: { type: Date, default: Date.now }
});

const productSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  image_url: { type: String },
  download_link: { type: String },
  video_url: { type: String },
  video_chapters: { type: Array, default: [] },
  features: { type: Array, default: [] },
  created_at: { type: Date, default: Date.now }
});

const cartSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  user_id: { type: String, required: true },
  items: [{
    product_id: String,
    quantity: { type: Number, default: 1 }
  }],
  updated_at: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
  id: { type: String, default: uuidv4, unique: true },
  user_id: { type: String, required: true },
  items: { type: Array, required: true },
  total: { type: Number, required: true },
  razorpay_order_id: { type: String, required: true },
  razorpay_payment_id: { type: String },
  status: { type: String, default: 'created' }, // created, paid, failed
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Cart = mongoose.model('Cart', cartSchema);
const Order = mongoose.model('Order', orderSchema);

// --- Middleware Helpers ---
const authMiddleware = async (req, res, next) => {
  await connectDB();
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ detail: "Invalid token" });

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const user = await User.findOne({ id: payload.sub });
    if (!user) return res.status(401).json({ detail: "User not found" });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ detail: "Token expired or invalid" });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ detail: "Admin access required" });
  }
  next();
};

const uploadToCloudinary = (buffer, folder, resource_type = "auto") => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: folder, resource_type: resource_type },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    );
    // Write buffer to stream
    const { Readable } = require('stream');
    const stream = new Readable();
    stream.push(buffer);
    stream.push(null);
    stream.pipe(uploadStream);
  });
};

// --- Routes ---

// Health Check
app.get('/api', (req, res) => res.send("FastAPI to Express: Server is Running"));

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  await connectDB();
  try {
    const { email, password, name } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ detail: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const demo_course_id = "12e942d3-1091-43f0-b22c-33508096276b";

    const user = new User({
      email,
      name,
      password_hash: hashedPassword,
      purchased_products: [demo_course_id]
    });
    await user.save();

    const token = jwt.sign({ sub: user.id }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    res.status(500).json({ detail: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  await connectDB();
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !user.password_hash) return res.status(401).json({ detail: "Invalid email or password" });

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) return res.status(401).json({ detail: "Invalid email or password" });

    const token = jwt.sign({ sub: user.id }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    res.status(500).json({ detail: e.message });
  }
});

app.post('/api/auth/clerk-sync', async (req, res) => {
  await connectDB();
  try {
    const { clerk_id, email, name, profile_image_url } = req.body;
    const existingUser = await User.findOne({ clerk_id });

    if (existingUser) {
      existingUser.name = name;
      existingUser.email = email;
      if (profile_image_url) existingUser.profile_image_url = profile_image_url;
      await existingUser.save();
      return res.json({ status: "updated", user: existingUser });
    } else {
      const demo_course_id = "12e942d3-1091-43f0-b22c-33508096276b";
      const user = new User({
        clerk_id, email, name, profile_image_url,
        purchased_products: [demo_course_id]
      });
      await user.save();
      return res.json({ status: "created", user });
    }
  } catch (e) {
    res.status(500).json({ detail: e.message });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    name: req.user.name,
    role: req.user.role,
    purchased_products: req.user.purchased_products
  });
});

// Product Routes
app.get('/api/products', async (req, res) => {
  await connectDB();
  const { category } = req.query;
  const query = category ? { category } : {};
  const products = await Product.find(query);
  res.json(products);
});

app.get('/api/products/:id', async (req, res) => {
  await connectDB();
  const product = await Product.findOne({ id: req.params.id });
  if (!product) return res.status(404).json({ detail: "Product not found" });
  res.json(product);
});

// Cart Routes
app.get('/api/cart', authMiddleware, async (req, res) => {
  await connectDB();
  const cart = await Cart.findOne({ user_id: req.user.id });
  if (!cart) return res.json({ items: [] });

  const itemsWithDetails = [];
  for (const item of cart.items) {
    const product = await Product.findOne({ id: item.product_id });
    if (product) {
      itemsWithDetails.push({ product, quantity: item.quantity });
    }
  }
  res.json({ items: itemsWithDetails });
});

app.post('/api/cart/add', authMiddleware, async (req, res) => {
  await connectDB();
  const { product_id, quantity } = req.body;
  
  const product = await Product.findOne({ id: product_id });
  if (!product) return res.status(404).json({ detail: "Product not found" });

  let cart = await Cart.findOne({ user_id: req.user.id });
  if (!cart) {
    cart = new Cart({ user_id: req.user.id, items: [{ product_id, quantity: quantity || 1 }] });
  } else {
    const exists = cart.items.find(i => i.product_id === product_id);
    if (exists) return res.status(400).json({ detail: "Product already in cart" });
    cart.items.push({ product_id, quantity: quantity || 1 });
    cart.updated_at = Date.now();
  }
  await cart.save();
  res.json({ message: "Item added to cart" });
});

app.delete('/api/cart/remove/:product_id', authMiddleware, async (req, res) => {
  await connectDB();
  const cart = await Cart.findOne({ user_id: req.user.id });
  if (!cart) return res.status(404).json({ detail: "Cart not found" });
  
  cart.items = cart.items.filter(i => i.product_id !== req.params.product_id);
  cart.updated_at = Date.now();
  await cart.save();
  res.json({ message: "Item removed from cart" });
});

app.delete('/api/cart/clear', authMiddleware, async (req, res) => {
  await connectDB();
  await Cart.updateOne({ user_id: req.user.id }, { $set: { items: [], updated_at: Date.now() } });
  res.json({ message: "Cart cleared" });
});

// Order & Payment Routes
app.post('/api/orders/create', authMiddleware, async (req, res) => {
  await connectDB();
  const cart = await Cart.findOne({ user_id: req.user.id });
  if (!cart || cart.items.length === 0) return res.status(400).json({ detail: "Cart is empty" });

  const items = [];
  let total = 0;
  for (const item of cart.items) {
    const product = await Product.findOne({ id: item.product_id });
    if (product) {
      items.push({
        product_id: product.id,
        name: product.name,
        price: product.price,
        quantity: item.quantity
      });
      total += product.price * item.quantity;
    }
  }

  try {
    const rzOrder = await razorpay.orders.create({
      amount: Math.round(total * 100), // paise
      currency: "INR",
      payment_capture: 1
    });

    const order = new Order({
      user_id: req.user.id,
      items,
      total,
      razorpay_order_id: rzOrder.id
    });
    await order.save();

    res.json({
      order_id: order.id,
      razorpay_order_id: rzOrder.id,
      amount: total,
      currency: "INR",
      key_id: process.env.RAZORPAY_KEY_ID
    });
  } catch (e) {
    res.status(500).json({ detail: e.message });
  }
});

app.post('/api/orders/verify', authMiddleware, async (req, res) => {
  await connectDB();
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, order_id } = req.body;

  try {
    const crypto = require('crypto');
    const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    const generated_signature = hmac.digest('hex');

    if (generated_signature !== razorpay_signature) {
       throw new Error("Invalid signature");
    }

    // Success
    const order = await Order.findOne({ id: order_id });
    if (!order) return res.status(404).json({ detail: "Order not found" });

    order.status = 'paid';
    order.razorpay_payment_id = razorpay_payment_id;
    await order.save();

    // Add to purchased
    const productIds = order.items.map(i => i.product_id);
    await User.updateOne({ id: req.user.id }, { $addToSet: { purchased_products: { $each: productIds } } });
    
    // Clear cart
    await Cart.updateOne({ user_id: req.user.id }, { $set: { items: [] } });

    res.json({ message: "Payment verified successfully", status: "paid" });

  } catch (e) {
    await Order.updateOne({ id: order_id }, { $set: { status: 'failed' } });
    res.status(400).json({ detail: "Payment verification failed" });
  }
});

app.get('/api/orders', authMiddleware, async (req, res) => {
  await connectDB();
  const orders = await Order.find({ user_id: req.user.id }).sort({ created_at: -1 });
  res.json(orders);
});

app.get('/api/purchased-products', authMiddleware, async (req, res) => {
  await connectDB();
  const ids = req.user.purchased_products || [];
  if (ids.length === 0) return res.json([]);
  const products = await Product.find({ id: { $in: ids } });
  res.json(products);
});

app.get('/api/clerk/purchased-products/:clerk_id', async (req, res) => {
  await connectDB();
  const user = await User.findOne({ clerk_id: req.params.clerk_id });
  if (!user || !user.purchased_products.length) return res.json([]);
  
  const products = await Product.find({ id: { $in: user.purchased_products } });
  res.json(products);
});

// Admin Routes (Using Multer for File Uploads)
const cpUpload = upload.fields([{ name: 'image', maxCount: 1 }, { name: 'download_file', maxCount: 1 }]);

app.post('/api/admin/products', authMiddleware, adminMiddleware, cpUpload, async (req, res) => {
  await connectDB();
  try {
    const { name, description, price, category, features, video_url, video_chapters } = req.body;
    let image_url = "";
    let download_link = "";

    // Upload Files
    if (req.files['image']) {
      const result = await uploadToCloudinary(req.files['image'][0].buffer, "ecommerce/products", "image");
      image_url = result.secure_url;
    }
    if (req.files['download_file']) {
      const result = await uploadToCloudinary(req.files['download_file'][0].buffer, "ecommerce/downloads", "auto");
      download_link = result.secure_url;
    }

    const newProduct = new Product({
      name, description, price, category,
      image_url, download_link,
      video_url: video_url || null,
      video_chapters: video_chapters ? JSON.parse(video_chapters) : [],
      features: features ? features.split(',').map(f => f.trim()).filter(f => f) : []
    });

    await newProduct.save();
    res.json(newProduct);
  } catch (e) {
    res.status(500).json({ detail: e.message });
  }
});

app.put('/api/admin/products/:id', authMiddleware, adminMiddleware, cpUpload, async (req, res) => {
  await connectDB();
  try {
    const product = await Product.findOne({ id: req.params.id });
    if (!product) return res.status(404).json({ detail: "Product not found" });

    const updateData = { ...req.body };
    // Cleanup complex fields
    if (updateData.features) updateData.features = updateData.features.split(',').map(f => f.trim()).filter(f => f);
    if (updateData.video_chapters) updateData.video_chapters = JSON.parse(updateData.video_chapters);

    // Upload New Files
    if (req.files && req.files['image']) {
      const result = await uploadToCloudinary(req.files['image'][0].buffer, "ecommerce/products", "image");
      updateData.image_url = result.secure_url;
    }
    if (req.files && req.files['download_file']) {
      const result = await uploadToCloudinary(req.files['download_file'][0].buffer, "ecommerce/downloads", "auto");
      updateData.download_link = result.secure_url;
    }

    await Product.updateOne({ id: req.params.id }, { $set: updateData });
    const updated = await Product.findOne({ id: req.params.id });
    res.json(updated);
  } catch (e) {
    res.status(500).json({ detail: e.message });
  }
});

app.delete('/api/admin/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await connectDB();
  await Product.deleteOne({ id: req.params.id });
  res.json({ message: "Product deleted" });
});

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  await connectDB();
  const total_users = await User.countDocuments({ role: 'user' });
  const total_products = await Product.countDocuments({});
  const total_orders = await Order.countDocuments({});
  const paid_orders = await Order.countDocuments({ status: 'paid' });

  const orders = await Order.find({ status: 'paid' });
  const total_revenue = orders.reduce((sum, o) => sum + o.total, 0);

  res.json({ total_users, total_products, total_orders, paid_orders, total_revenue });
});

app.post('/api/admin/seed', async (req, res) => {
  await connectDB();
  const existing = await User.findOne({ email: "admin@digitalstore.com" });
  if (existing) return res.json({ message: "Admin already exists" });

  const hashedPassword = await bcrypt.hash("admin123", 10);
  const admin = new User({
    email: "admin@digitalstore.com",
    name: "Admin",
    role: "admin",
    password_hash: hashedPassword
  });
  await admin.save();
  res.json({ message: "Admin created", email: admin.email });
});

module.exports = app;

// ... (Your existing code ending with module.exports = app)

