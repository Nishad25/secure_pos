const Razorpay = require("razorpay");
const createHttpError = require("http-errors");
const config = require("../config/config");
const crypto = require("crypto");
const Payment = require("../models/paymentModel");

const createOrder = async (req, res, next) => {
  const razorpay = new Razorpay({
    key_id: config.razorpayKeyId,
    key_secret: config.razorpaySecretKey,
  });

  try {
    const { amount } = req.body;
    const options = {
      amount: amount * 100, // Amount in paisa (1 INR = 100 paisa)
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);
    res.status(200).json({ success: true, order });
  } catch (error) {
    console.log(error);
    next(error);
  }
};

const verifyPayment = async (req, res, next) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
      req.body;

    const expectedSignature = crypto
      .createHmac("sha256", config.razorpaySecretKey)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");

    if (expectedSignature === razorpay_signature) {
      res.json({ success: true, message: "Payment verified successfully!" });
    } else {
      const error = createHttpError(400, "Payment verification failed!");
      return next(error);
    }
  } catch (error) {
    next(error);
  }
};

const webHookVerification = async (req, res, next) => {
  try {
    const secret = config.razorpyWebhookSecret;
    const signature = req.headers["x-razorpay-signature"];

    const body = JSON.stringify(req.body);

    // 🛑 Verify the signature
    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex");

    if (expectedSignature === signature) {
      console.log("✅ Webhook verified:", req.body);

      // ✅ Process payment (e.g., update DB, send confirmation email)
      if (req.body.event === "payment.captured") {
        const payment = req.body.payload.payment.entity;
        console.log(`💰 Payment Captured: ${payment.amount / 100} INR`);

        // Add Payment Details in Database
        const newPayment = new Payment({
          paymentId: payment.id,
          orderId: payment.order_id,
          amount: payment.amount / 100,
          currency: payment.currency,
          status: payment.status,
          method: payment.method,
          email: payment.email,
          contact: payment.contact,
          createdAt: new Date(payment.created_at * 1000) 
        })

        await newPayment.save();
      }

      res.json({ success: true });
    } else {
      const error = createHttpError(400, "❌ Invalid Signature!");
      return next(error);
    }
  } catch (error) {
    next(error);
  }
};

const payWithCard = async (req, res, next) => {
  try {
    const {
      cardHolderName,
      cardNumber,
      cardType,
      expiryMonth,
      expiryYear,
      cvv,
      amount,
      customerEmail,
    } = req.body;

    if (!cardHolderName || !cardNumber || !expiryMonth || !expiryYear || !cvv || !amount) {
      const error = createHttpError(400, "All card details are required!");
      return next(error);
    }

    const gatewayResponse = await fetch(
      `${config.fakePaymentGatewayUrl}/api/v1/payment/card`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          app_name: "RESTRO POS",
          service: "Restaurant Order",
          customer_email: customerEmail || "guest@restro-pos.com",
          card_type: cardType || "VISA",
          card_holder_name: cardHolderName,
          card_number: cardNumber,
          expiryMonth,
          expiryYear,
          cvv,
          amount: String(amount),
          currency: "INR",
        }),
      }
    );

    const gatewayData = await gatewayResponse.json();

    if (!gatewayResponse.ok || !gatewayData.success) {
      const error = createHttpError(
        402,
        gatewayData.message || "Payment declined by payment gateway!"
      );
      return next(error);
    }

    const transactionId = `txn_${Date.now()}`;

    const newPayment = new Payment({
      paymentId: transactionId,
      amount,
      currency: "INR",
      status: "captured",
      method: "card",
      email: customerEmail,
      createdAt: new Date(),
    });
    await newPayment.save();

    res.status(200).json({
      success: true,
      message: "Payment successful!",
      data: { transactionId },
    });
  } catch (error) {
    if (error.cause && error.cause.code === "ECONNREFUSED") {
      return next(
        createHttpError(
          503,
          "Payment gateway is unreachable. Is fake-payment-gateway running on port 5100?"
        )
      );
    }
    next(error);
  }
};

module.exports = { createOrder, verifyPayment, webHookVerification, payWithCard };
