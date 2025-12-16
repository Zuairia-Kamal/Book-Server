
require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { MongoClient, ObjectId, ServerApiVersion } = require('mongodb')
const admin = require('firebase-admin')
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)
const path = require("path");
const fs = require("fs");
const app = express()
const PORT = process.env.PORT || 3000
let ReviewsCollection;

// ---------- Firebase Admin ----------
if (!process.env.FIREBASE_SERVICE_KEY) {
  console.warn('FIREBASE_SERVICE_KEY not set — protected routes will fail')
} else {
  const decoded = Buffer.from(process.env.FIREBASE_SERVICE_KEY, 'base64').toString('utf8')
  const serviceAccount = JSON.parse(decoded)
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) })
  console.log('Firebase Admin initialized')
}

// ---------- Middleware ----------
const ALLOWED_ORIGINS = [process.env.CLIENT_DOMAIN || 'http://localhost:5173', "https://helpful-entremet-42b72d.netlify.app/"]
app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }))
app.use(express.json())

// ---------- MongoDB ----------
const client = new MongoClient(process.env.MONGO_URI, { serverApi: { version: ServerApiVersion.v1 } })
let db
let Users, Books, Orders, Reviews, SellerRequests, Wishlists, Invoices, LatestBooks

const fileUpload = require("express-fileupload");

app.use(
  fileUpload({
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    createParentPath: true,
  })
);

async function connectDB() {
  await client.connect()
  db = client.db(process.env.DB_NAME || 'BookRecord')

  Users = db.collection('Users')
  Books = db.collection('BookCollection')       
  Orders = db.collection('Orders') 
 ReviewsCollection = db.collection('Reviews')
  // SellerRequests = db.collection('sellerRequests')
   Wishlists = db.collection('wishlist')
  Invoices = db.collection("invoices");
  LatestBooks = db.collection('Latest')
  
  console.log('MongoDB connected')
}
connectDB();

// ---------- Helpers ----------
const toObjectId = id => {
  try { return new ObjectId(id) } catch { return null }
}

// Firebase token verification
// const verifyJWT = async (req, res, next) => {
//   const token = req?.headers?.authorization?.split(' ')[1];
//   if (!token) return res.status(401).send({ message: 'Unauthorized Access!' });

//   try {
//     const decoded = await admin.auth().verifyIdToken(token);
//     req.tokenEmail = decoded.email;

//     // Fetch role from MongoDB
//     // const user = await Users.findOne({ email: decoded.email });
//     // req.tokenRole = user?.role; // <-- important!
//     const user = await Users.findOne({ email: decoded.email });
// req.tokenRole = user?.role;

//     next();
//   } catch (err) {
//     console.log(err);
//     return res.status(401).send({ message: 'Unauthorized Access!', err });
//   }
// };
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  console.log("TOKEN RECEIVED:", token ? "YES" : "NO");

  if (!token) return res.status(401).send({ message: "Unauthorized" });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    console.log("DECODED EMAIL:", decoded.email);

    const user = await Users.findOne({ email: decoded.email });
    console.log("USER FROM DB:", user);

    req.tokenEmail = decoded.email;
    req.tokenRole = user?.role;

    next();
  } catch (err) {
    console.log("JWT ERROR:", err.message);
    return res.status(401).send({ message: "Unauthorized" });
  }
};

// const verifyRole = (role) => {
//   return (req, res, next) => {
//     if (!req.tokenRole) {
//       return res.status(403).json({ message: "Forbidden" });
//     }

//     if (req.tokenRole !== role && req.tokenRole !== "admin") {
//       return res.status(403).json({ message: "Not authorized for this role" });
//     }

//     next();
//   };
// };
const verifyRole = (role) => {
  return (req, res, next) => {
    console.log("ROLE REQUIRED:", role);
    console.log("ROLE FOUND:", req.tokenRole);

    if (!req.tokenRole) {
      return res.status(403).json({ message: "No role found" });
    }

    if (req.tokenRole !== role && req.tokenRole !== "admin") {
      return res.status(403).json({ message: "Forbidden" });
    }

    next();
  };
};


// Role middlewares
const verifyADMIN = async (req, res, next) => {
  const user = await Users.findOne({ email: req.tokenEmail })
  if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Admin only action' })
  next()
}
const verifySELLER = (req, res, next) => {
  if (!["seller", "librarian", "admin"].includes(req.tokenRole)) {
    return res.status(403).json({ message: "Forbidden" });
  }
  next();
};

// Middleware to verify Firebase token
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    req.tokenEmail = null;
    return next();
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (err) {
    console.error("Token error:", err);
    req.tokenEmail = null;
    next();
  }
};
app.get('/', (req, res) => res.send('BookCourier API running'))


// Attach logged-in user's role from DB
const attachUserRole = async (req, res, next) => {
  try {
    const user = await Users.findOne({ email: req.tokenEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });
    req.role = user.role;      // "user", "librarian", "admin", "seller"
    req.userData = user;       
    next();
  } catch (err) { console.error(err); res.status(500).send(err); }
};


// app.post("/books", verifyJWT, verifySELLER, async (req, res) => {
//   try {
//     const { title, author, price, status } = req.body;

//     const newBook = {
//       title,
//       author,
//       price: Number(price),
//       status,
//       sellerEmail: req.tokenEmail,
//       createdAt: new Date(),
//     };

//     const result = await Books.insertOne(newBook);
//     res.json({ message: "Book added", book: newBook });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Server error" });
//   }
// });

/* ---------------- USERS(called after Firebase sign-in) ---------------- */
app.patch('/user/role', verifyJWT, verifyADMIN, async (req, res) => {
  const { email, role } = req.body;
  const result = await Users.updateOne({ email }, { $set: { role } });
  res.json(result);
});

app.post('/user', async (req, res) => {
  try {
    const { email, name, role, photo } = req.body
    if (!email) return res.status(400).json({ message: 'Missing email' })
    const now = new Date()
    const update = {
      $set: { email, name: name || null, photo: photo || null, role: role || 'customer', lastLoggedIn: now },
      $setOnInsert: { createdAt: now }
    }
    const result = await Users.updateOne({ email }, update, { upsert: true })
    res.json({ message: 'User added/updated', result })
  } catch (err) {
    console.error('/user', err)
    res.status(500).json({ message: 'Server error' })
  }
})
// "seller", "librarian", "admin"
app.patch('/users/upgrade-role', verifyJWT, async (req, res) => {
  try {
    const { newRole } = req.body; 
    const email = req.tokenEmail;

    const user = await Users.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Only admin can make someone admin or librarian
    if ((newRole === 'admin' || newRole === 'librarian') && user.role !== 'admin') {
      return res.status(403).json({ message: 'Not authorized' });
    }

    await Users.updateOne({ email }, { $set: { role: newRole } });
    res.json({ message: `User is now a ${newRole}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get current user info
app.get('/user/me', verifyJWT, async (req, res) => {
  const user = await Users.findOne({ email: req.tokenEmail })
  res.json(user || null)
})
app.get("/user/:email", async (req, res) => {
  try {
    const email = req.params.email;

    const user = await Users.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("GET /user/:email error:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// Get user role for useRole hook
app.get("/user/role", async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ role: null });
  }

  const user = await usersCollection.findOne({ email });

  if (!user) {
    return res.status(404).json({ role: null });
  }

  res.json({ role: user.role });
});

// Admin: list users (except self)
app.get('/users', verifyJWT, verifyADMIN, async (req, res) => {
  const users = await Users.find({ email: { $ne: req.tokenEmail } }).toArray()
  res.json(users)
})

// Admin: update role (make librarian/seller or admin)
app.patch('/update-role', verifyJWT, verifyADMIN, async (req, res) => {
  try {
    const { email, role } = req.body;
    if (!email || !role)
      return res.status(400).json({ message: 'Missing fields' });

    const result = await Users.updateOne({ email }, { $set: { role } });

    if (role === 'seller') await SellerRequests.deleteOne({ email });

    res.json({ message: 'Role updated', result });
  } catch (err) {
    console.error('/update-role', err);
    res.status(500).json({ message: 'Server error' });
  }
});


/* ---------------- SELLER REQUESTS ---------------- */

app.post('/become-seller', verifyJWT, async (req, res) => {
  try {
    const email = req.tokenEmail
    const exists = await SellerRequests.findOne({ email })
    if (exists) return res.status(409).json({ message: 'Already requested' })
    const result = await SellerRequests.insertOne({ email, createdAt: new Date() })
    res.json(result)
  } catch (err) {
    console.error('/become-seller', err)
    res.status(500).json({ message: 'Server error' })
  }
})

app.get('/seller-requests', verifyJWT, verifyADMIN, async (req, res) => {
  const list = await SellerRequests.find().toArray()
  res.json(list)
})

/* ---------------- BOOKS ---------------- */
// Create book-liby

app.post("/books", verifyJWT, verifyRole("librarian"), async (req, res) => {
  try {
    const { title, author, price, status } = req.body;

    if (!title || !author || !price || !status) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Handle image upload
    let imageUrl = "";
    if (req.files && req.files.image) {
      const image = req.files.image;
      const uploadDir = path.join(__dirname, "uploads");

      if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

      const uploadPath = path.join(uploadDir, image.name);
      await image.mv(uploadPath);

      imageUrl = `/uploads/${image.name}`;
    }

    const newBook = {
      title,
      author,
      price: Number(price),
      status,
      image: imageUrl,
      createdAt: new Date(),
      librarianEmail: req.tokenEmail,
      quantity: req.body.quantity ?? 1,
    };

    const result = await Books.insertOne(newBook);
    newBook._id = result.insertedId;

    res.json({ message: "Book added successfully", book: newBook });
  } catch (err) {
    console.error("POST /books error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get books (supports search q, sort, latest, category, published)
app.get('/books', async (req, res) => {
  try {
    const { q, sort, latest, category, published } = req.query
    const filter = {}
    if (q) filter.$or = [{ title: { $regex: q, $options: 'i' } }, { author: { $regex: q, $options: 'i' } }]
    if (category) filter.category = category
    if (published !== undefined) filter.published = (published === 'true')

    let cursor = Books.find(filter)
    if (latest === 'true') cursor = cursor.sort({ createdAt: -1 }).limit(6)
    if (sort === 'price_asc') cursor = cursor.sort({ price: 1 })
    if (sort === 'price_desc') cursor = cursor.sort({ price: -1 })

    const list = await cursor.toArray()
    res.json(list)
  } catch (err) {
    console.error('GET /books', err)
    res.status(500).json({ message: 'Server error' })
  }
})

// Get a single book by ID
app.get('/books/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const book = await Books.findOne({ _id: toObjectId(id) }); // convert string to ObjectId
    if (!book) return res.status(404).json({ message: 'Book not found' });
    res.json(book);
  } catch (err) {
    console.error('GET /books/:id', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update book (seller)
app.put('/books/:id', verifyJWT, verifySELLER, async (req, res) => {
  const bookId = toObjectId(req.params.id);
  const updates = req.body;

  const book = await Books.findOne({ _id: bookId });
  if (!book) return res.status(404).json({ message: 'Book not found' });

  // Only owner or admin can edit
  const requesterRole = req.tokenRole;
  if (requesterRole !== 'admin' && book.librarianEmail !== req.tokenEmail) {
    return res.status(403).json({ message: 'Not authorized' });
  }

  await Books.updateOne({ _id: bookId }, { $set: updates });
  res.json({ message: 'Book updated' });
});


// PUT /users/:id/role
app.put("/users/:id/role", verifyJWT, async (req, res) => {
  const { role } = req.body;
  const userId = req.params.id;

  // Only admin can update roles
  if (req.tokenRole !== "admin") return res.status(403).json({ message: "Forbidden" });

  const result = await Users.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { role } }
  );

  res.json({ message: "Role updated", result });
});


// Publish / Unpublish (admin or owner
app.patch("/books/:id/publish", verifyJWT, verifySELLER, async (req, res) => {
  const { publish } = req.body;
  const bookId = toObjectId(req.params.id);

  const book = await Books.findOne({ _id: bookId });
  if (!book) return res.status(404).json({ message: "Book not found" });

  const requesterRole = req.tokenRole;
  if (requesterRole !== "librarian" && requesterRole !== "admin") {
    return res.status(403).json({ message: "Forbidden" });
  }

  await Books.updateOne({ _id: bookId }, { $set: { status: publish ? "published" : "draft" } });
  res.json({ status: publish ? "published" : "draft" });
});



app.patch("/books/:id", verifyJWT, async (req, res) => {
  const bookId = req.params.id;
  const { title, price, author, image } = req.body;

  const book = await Books.findOne({ _id: toObjectId(bookId) });
  if (!book) return res.status(404).json({ message: "Book not found" });

  // ⚠️ Check role
  if (req.tokenRole !== "librarian") {
    return res.status(403).json({ message: "Forbidden" });
  }

  await Books.updateOne(
    { _id: toObjectId(bookId) },
    { $set: { title, price, author, image } }
  );

  res.json({ message: "Book updated" });
});



// Delete book (admin only) — cascade delete orders & reviews & wishlist entries
app.delete('/books/:id', verifyJWT, verifyADMIN, async (req, res) => {
  try {
    const id = toObjectId(req.params.id)
    if (!id) return res.status(400).json({ message: 'Invalid id' })

    await Orders.deleteMany({ bookId: req.params.id })
    await ReviewsCollection.deleteMany({ bookId: req.params.id })
    await Wishlists.deleteMany({ bookId: req.params.id })
    const result = await Books.deleteOne({ _id: id })
    res.json({ message: 'Book and related data deleted', result })
  } catch (err) {
    console.error('DELETE /books/:id', err)
    res.status(500).json({ message: 'Server error' })
  }
})

/* ---------------- WISHLIST ---------------- */
// app.post('/wishlist', verifyJWT, async (req, res) => {
//   try {
//     const { bookId } = req.body
//     if (!bookId) return res.status(400).json({ message: 'Missing bookId' })
//     const exists = await Wishlists.findOne({ bookId, userEmail: req.tokenEmail })
//     if (exists) return res.status(409).json({ message: 'Already in wishlist' })
//     const result = await Wishlists.insertOne({ bookId, userEmail: req.tokenEmail, createdAt: new Date() })
//     res.json(result)
//   } catch (err) {
//     console.error('/wishlist POST', err)
//     res.status(500).json({ message: 'Server error' })
//   }
// })
// app.get('/wishlist', verifyJWT, async (req, res) => {
//   const items = await Wishlists.find({ userEmail: req.tokenEmail }).toArray()
//   res.json(items)
// })
// app.delete('/wishlist/:bookId', verifyJWT, async (req, res) => {
//   const { bookId } = req.params
//   const result = await Wishlists.deleteOne({ bookId, userEmail: req.tokenEmail })
//   res.json(result)
// })

/* ---------------- REVIEWS ---------------- */

app.post('/reviews', verifyJWT, async (req, res) => {
  try {
    const { bookId, rating, comment } = req.body;

    if (!bookId || rating === undefined) {
      return res.status(400).json({ message: 'Missing fields' });
    }


    const review = {
      bookId: bookId.toString(),
      rating,
      comment: comment || '',
      userEmail: req.tokenEmail,
      createdAt: new Date()
    };

    const result = await ReviewsCollection.insertOne(review);
    res.json(result);

  } catch (err) {
    console.error('/reviews POST', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get("/reviews", async (req, res) => {
  const { bookId } = req.query;
  if (!bookId) return res.status(400).send({ error: "bookId is required" });

  try {
    const reviews = await ReviewsCollection.find({ bookId: bookId.toString() }).toArray();
    res.send(reviews);
  } catch (err) {
    console.error('/reviews GET', err);
    res.status(500).send({ error: "Failed to fetch reviews" });
  }
});
app.get("/reviews-latest", async (req, res) => {
  try {
    const reviews = await ReviewsCollection.find({})
      .sort({ createdAt: -1 })
      .limit(10) // top 10 latest reviews
      .toArray();
    res.json(reviews);
  } catch (err) {
    console.error('/reviews-latest GET', err);
    res.status(500).send({ error: "Failed to fetch latest reviews" });
  }
});
app.get('/reviews/:bookId', async (req, res) => {
  try {
    const reviews = await ReviewsCollection.find({ bookId: req.params.bookId.toString() }).toArray();
    res.json(reviews);
  } catch (err) {
    console.error('/reviews/:bookId GET', err);
    res.status(500).send({ error: "Failed to fetch reviews" });
  }
});

// Admin-only routes
// app.get("/admin/orders", verifyJWT, verifyRole("admin"), async (req, res) => {
//   try {
//     const list = await Orders.find().sort({ createdAt: -1 }).toArray();
//     res.json(list);
//   } catch (err) {
//     console.error("GET /admin/orders", err);
//     res.status(500).json({ message: "Server error" });
//   }
// });

// // Librarian-only routes
// app.get("/seller/orders", verifyJWT, verifyRole("librarian"), async (req, res) => {
//   try {
//     const list = await Orders.find({ "seller.email": req.tokenEmail }).toArray();
//     res.json(list);
//   } catch (err) {
//     console.error("GET /seller/orders", err);
//     res.status(500).json({ message: "Server error" });
//   }
// });

// User-only routes
// app.get("/orders", verifyJWT, verifyRole("customer"), async (req, res) => {
//   const { bookId } = req.query;
//   if (!bookId) return res.status(400).json({ message: "Missing bookId" });

//   const orders = await Orders.find({
//     bookId: bookId.toString(),
//     userEmail: req.tokenEmail
//   }).toArray();

//   res.json(orders);
// });
// app.get("/orders", verifyToken, async (req, res) => {
//   const email = req.query.email;

//   if (req.decoded.email !== email) {
//     return res.status(403).json({ message: "Forbidden" });
//   }

//   const orders = await ordersCollection
//     .find({ userEmail: email })
//     .toArray();

//   res.json(orders);
// });


// POST /user - create or update user
app.post("/user", async (req, res) => {
  try {
    const { email, name, photo, role } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const now = new Date();
    const update = {
      $set: { email, name: name || null, photo, role: role || "customer", lastLoggedIn: now },
      $setOnInsert: { createdAt: now },
    };

    const result = await Users.updateOne({ email }, update, { upsert: true });
    res.json({ message: "User added/updated", result });
  } catch (err) {
    console.error("POST /user error", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /user?email=... - get user by email
app.get("/user", verifyToken, async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await Users.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({
      email: user.email,
      name: user.name,
      role: user.role,
      photoURL: user.photo,
    });
  } catch (err) {
    console.error("GET /user error", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- LATEST BOOKS ---------------- */
app.post('/books/latest/:id', verifyJWT, verifyADMIN, async (req, res) => {
  try {
    const id = toObjectId(req.params.id)
    if (!id) return res.status(400).json({ message: "Invalid book id" })

    const book = await Books.findOne({ _id: id })
    if (!book) return res.status(404).json({ message: "Book not found" })

    // Check if already added
    const exists = await LatestBooks.findOne({ bookId: id.toString() })
    if (exists) return res.status(409).json({ message: "Already in Latest" })

    const doc = {
      bookId: id.toString(),
      addedAt: new Date(),
      title: book.title,
      price: book.price,
      image: book.image,
      category: book.category,
      seller: book.seller
    }

    const result = await LatestBooks.insertOne(doc)
    res.json({ message: "Added to Latest Books", result })

  } catch (err) {
    console.error("POST /books/latest/:id", err)
    res.status(500).json({ message: "Server error" })
  }
})


// Remove a book from Latest
app.delete('/books/latest/:id', verifyJWT, verifyADMIN, async (req, res) => {
  try {
    const result = await LatestBooks.deleteOne({ bookId: req.params.id })
    res.json({ message: "Removed from Latest Books", result })
  } catch (err) {
    console.error("DELETE /books/latest/:id", err)
    res.status(500).json({ message: "Server error" })
  }
})


// Get Latest Books
app.get('/books-latest', async (req, res) => {
  try {
    const list = await LatestBooks.find().sort({ addedAt: -1 }).toArray()
    res.json(list)
  } catch (err) {
    console.error("GET /books-latest", err)
    res.status(500).json({ message: "Server error" })
  }
})

/* ---------------- ORDERS & PAYMENTS (Stripe) ---------------- */

// Create an order (without immediate payment) — legacy/simple order endpoint
app.post('/orders', verifyJWT, async (req, res) => {
  try {
    const { bookId, phone, address } = req.body;
    if (!bookId || !address) return res.status(400).json({ message: 'Missing fields' });

    const book = await Books.findOne({ _id: toObjectId(bookId) });
    if (!book) return res.status(404).json({ message: 'Book not found' });

    const order = {
      bookId,
      title: book.title,
      price: book.price,   // ← Add price
      userEmail: req.tokenEmail,
      phone,
      address,
      status: 'pending',
      paymentStatus: 'unpaid',
      createdAt: new Date()
    };

    const result = await Orders.insertOne(order);
    res.json({ orderId: result.insertedId });
  } catch (err) {
    console.error('POST /orders', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create checkout session (Stripe) — frontend redirects to session.url
app.post("/create-checkout-session", verifyJWT, async (req, res) => {
  try {
    const { bookId, price, quantity, title } = req.body; 
    if (!bookId || !price || !title) return res.status(400).json({ message: "Missing fields" });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: { name: title },
            unit_amount: Math.round(price * 100),
          },
          quantity: quantity || 1,
        },
      ],
      mode: "payment",
      metadata: {
        bookId,
        customer: req.tokenEmail,
      },
      // Pass session ID in path
      success_url: "http://localhost:5173/dashboard/payment/{CHECKOUT_SESSION_ID}",
      cancel_url: "http://localhost:5173/dashboard/my-orders",
    });

    res.json({ url: session.url });

  } catch (error) {
    console.error("Stripe Error:", error);
    res.status(500).json({ error: error.message });
  }
});


// Payment success (called from frontend when success page loads)
app.post('/payment-success', async (req, res) => {
  try {
    const { sessionId } = req.body;

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    const bookId = session.metadata?.bookId;
    const customer = session.metadata?.customer;

    if (!bookId) return res.status(400).json({ message: 'Missing bookId' });

    const book = await Books.findOne({ _id: toObjectId(bookId) });
    if (!book) return res.status(404).json({ message: 'Book not found' });

    const existingOrder = await Orders.findOne({
      transactionId: session.payment_intent
    });

    if (!existingOrder && session.payment_status === "paid") {
      const newOrder = {
        bookId,
        title: book.title,
        transactionId: session.payment_intent,
        customer,
        quantity: 1,
        price: session.amount_total / 100,
        paymentStatus: "paid",
        status: "pending",
        createdAt: new Date(),
      };
      await Orders.insertOne(newOrder);

      // Reduce book quantity
      if (typeof book.quantity === "number") {
        await Books.updateOne({ _id: book._id }, { $inc: { quantity: -1 } });
      }

      return res.json({ message: 'Order created', orderId: newOrder._id });
    }

    res.json({ message: 'Order already exists', orderId: existingOrder?._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Payment verification failed' });
  }
});


// Get user's orders
app.get('/my-orders', verifyJWT, async (req, res) => {
  const list = await Orders.find({ customer: req.tokenEmail }).toArray()
  res.json(list)
})
// POST /create-order
const createOrder = async (req, res) => {
  try {
    const { bookId, userEmail, quantity, price, title } = req.body;

    const newOrder = {
      _id: new mongoose.Types.ObjectId(), // unique order ID
      bookId,
      userEmail,
      bookTitle: title,
      quantity,
      price,
      status: "pending",
      paymentStatus: "unpaid",
      createdAt: new Date(),
    };

    // 1️⃣ Add order to User
    await User.updateOne(
      { email: userEmail },
      { $push: { orders: newOrder } }
    );

    // 2️⃣ Add order to Book
    await Book.updateOne(
      { _id: bookId },
      { $push: { orders: newOrder } }
    );

    res.status(201).json({ message: "Order created", order: newOrder });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to create order" });
  }
};
// GET /books
const getMyBooks = async (req, res) => {
  try {
    const userId = req.user.id; // Firebase or backend-authenticated
    const books = await Book.find({ authorId: userId }).lean();
    res.json(books);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch books" });
  }
};


// Cancel order (customer) — only pending orders allowed
app.patch('/orders/:id/cancel', verifyJWT, async (req, res) => {
  try {
    const id = toObjectId(req.params.id)
    if (!id) return res.status(400).json({ message: 'Invalid id' })
    const order = await Orders.findOne({ _id: id })
    if (!order) return res.status(404).json({ message: 'Order not found' })
    if (order.customer !== req.tokenEmail && order.userEmail !== req.tokenEmail) {
      return res.status(403).json({ message: 'Not authorized' })
    }
    if (order.status !== 'pending') return res.status(400).json({ message: 'Only pending orders can be cancelled' })
    const result = await Orders.updateOne({ _id: id }, { $set: { status: 'cancelled', updatedAt: new Date() } })
    res.json({ message: 'Order cancelled', result })
  } catch (err) {
    console.error('PATCH /orders/:id/cancel', err)
    res.status(500).json({ message: 'Server error' })
  }
})

// Seller: get orders for seller
app.get('/seller/orders', verifyJWT, verifySELLER, async (req, res) => {
  const list = await Orders.find({ 'seller.email': req.tokenEmail }).toArray()
  res.json(list)
})

// Update order status (seller or admin)
app.patch('/orders/:id/status', verifyJWT, async (req, res) => {
  try {
    const id = toObjectId(req.params.id)
    const { status } = req.body
    if (!id || !status) return res.status(400).json({ message: 'Missing fields' })
    const order = await Orders.findOne({ _id: id })
    if (!order) return res.status(404).json({ message: 'Order not found' })

    const requester = await Users.findOne({ email: req.tokenEmail })
    if (requester.role !== 'admin' && order.seller?.email !== req.tokenEmail) {
      return res.status(403).json({ message: 'Not authorized' })
    }

    const result = await Orders.updateOne({ _id: id }, { $set: { status, updatedAt: new Date() } })
    res.json({ message: 'Order status updated', result })
  } catch (err) {
    console.error('PATCH /orders/:id/status', err)
    res.status(500).json({ message: 'Server error' })
  }
})

/* ---------------- INVOICES ---------------- */
app.get('/invoices', verifyJWT, async (req, res) => {
  try {
    const invoices = await Invoices.find({ userEmail: req.tokenEmail }).toArray();
    res.json(invoices);
  } catch (err) {
    console.error("GET /invoices", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- SELLER ORDERS ---------------- */
app.get('/seller/orders', verifyJWT, verifySELLER, async (req, res) => {
  try {
    const list = await Orders.find({ "seller.email": req.tokenEmail }).toArray()
    res.json(list)
  } catch (err) {
    console.error("GET /seller/orders", err)
    res.status(500).json({ message: "Server error" })
  }
})
app.post("/orders", verifyJWT, verifyRole("customer"), async (req, res) => {
  const order = {
    ...req.body,
    userEmail: req.tokenEmail,
    status: "pending",
    paymentStatus: "unpaid",
    createdAt: new Date()
  };

  const result = await Orders.insertOne(order);
  order._id = result.insertedId;
  res.json(order);
});


// Get all orders
app.get('/orders', verifyJWT, async (req, res) => {
  try {
    const { bookId, email } = req.query;

    if (!bookId || !email) {
      return res.status(400).json({ message: "Missing bookId or email" });
    }

    const orders = await Orders.find({
      bookId: bookId.toString(),
      $or: [
        { customer: email },
        { userEmail: email }
      ]
    }).toArray();

    res.json(orders);

  } catch (err) {
    console.error("GET /orders error", err);
    res.status(500).json({ message: "Server error" });
  }
});


// Update order status
app.patch("/orders/:id", async (req, res) => {
  try {
    const id = toObjectId(req.params.id);
    const result = await Orders.updateOne(
      { _id: id },
      { $set: req.body }
    );
    res.json(result);
  } catch (err) {
    console.error("PATCH /orders/:id", err);
    res.status(500).json({ message: "Server error" });
  }
});
app.patch("/orders/:id/pay", verifyJWT, async (req, res) => {
  try {
    const id = toObjectId(req.params.id);
    if (!id) return res.status(400).json({ message: "Invalid order ID" });

    // Find the order
    const order = await Orders.findOne({ _id: id });
    if (!order) return res.status(404).json({ message: "Order not found" });

    // Mark as paid
    await Orders.updateOne(
      { _id: id },
      {
        $set: {
          paymentStatus: "paid",
          status: "completed",
          paidAt: new Date(),
        },
      }
    );

    // Create invoice
    const invoice = {
      orderId: id.toString(),
      bookId: order.bookId,
      userEmail: order.userEmail,
      amount: order.price || order.amount || 0,
      createdAt: new Date(),
    };

    await db.collection("invoices").insertOne(invoice);

    res.json({ message: "Payment successful", invoice });
  } catch (err) {
    console.error("PATCH /orders/:id/pay", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get invoice by order ID for user
app.get('/invoice/:orderId', verifyJWT, async (req, res) => {
  try {
    const invoice = await Invoices.findOne({ orderId: toObjectId(req.params.orderId) })
    if (!invoice) return res.status(404).json({ message: "Invoice not found" })
    if (invoice.userEmail !== req.tokenEmail) {
      return res.status(403).json({ message: "Not your invoice" })
    }
    res.json(invoice)
  } catch (err) {
    console.error("GET /invoice/:orderId", err)
    res.status(500).json({ message: "Server error" })
  }
})


/* ---------------- ADMIN: ALL ORDERS ---------------- */
app.get('/admin/orders', verifyJWT, verifyADMIN, async (req, res) => {
  try {
    const list = await Orders.find().sort({ createdAt: -1 }).toArray()
    res.json(list)
  } catch (err) {
    console.error("GET /admin/orders", err)
    res.status(500).json({ message: "Server error" })
  }
})

/* ---------------- SERVER START ---------------- */
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})

