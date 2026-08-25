import React, { useState } from "react";
import Modal from "../shared/Modal";

const CardPaymentModal = ({ isOpen, onClose, onSubmit, amount, isProcessing }) => {
  const [cardData, setCardData] = useState({
    cardHolderName: "",
    cardNumber: "",
    expiryMonth: "",
    expiryYear: "",
    cvv: "",
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setCardData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit(cardData);
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Card Payment">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <p className="text-[#ababab] text-sm">
          Amount to pay: <span className="text-[#f5f5f5] font-semibold">₹{amount}</span>
        </p>

        <div>
          <label className="text-xs text-[#ababab]">Card Holder Name</label>
          <input
            type="text"
            name="cardHolderName"
            value={cardData.cardHolderName}
            onChange={handleChange}
            required
            placeholder="Name on card"
            className="w-full mt-1 bg-[#1f1f1f] text-[#f5f5f5] rounded-lg px-4 py-2 outline-none"
          />
        </div>

        <div>
          <label className="text-xs text-[#ababab]">Card Number</label>
          <input
            type="text"
            name="cardNumber"
            value={cardData.cardNumber}
            onChange={handleChange}
            required
            maxLength={16}
            placeholder="4242424242424242"
            className="w-full mt-1 bg-[#1f1f1f] text-[#f5f5f5] rounded-lg px-4 py-2 outline-none"
          />
        </div>

        <div className="flex gap-3">
          <div className="flex-1">
            <label className="text-xs text-[#ababab]">Expiry Month</label>
            <input
              type="text"
              name="expiryMonth"
              value={cardData.expiryMonth}
              onChange={handleChange}
              required
              maxLength={2}
              placeholder="MM"
              className="w-full mt-1 bg-[#1f1f1f] text-[#f5f5f5] rounded-lg px-4 py-2 outline-none"
            />
          </div>
          <div className="flex-1">
            <label className="text-xs text-[#ababab]">Expiry Year</label>
            <input
              type="text"
              name="expiryYear"
              value={cardData.expiryYear}
              onChange={handleChange}
              required
              maxLength={4}
              placeholder="YYYY"
              className="w-full mt-1 bg-[#1f1f1f] text-[#f5f5f5] rounded-lg px-4 py-2 outline-none"
            />
          </div>
          <div className="flex-1">
            <label className="text-xs text-[#ababab]">CVV</label>
            <input
              type="password"
              name="cvv"
              value={cardData.cvv}
              onChange={handleChange}
              required
              maxLength={3}
              placeholder="123"
              className="w-full mt-1 bg-[#1f1f1f] text-[#f5f5f5] rounded-lg px-4 py-2 outline-none"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={isProcessing}
          className="bg-[#f6b100] disabled:opacity-50 px-4 py-3 w-full rounded-lg text-[#1f1f1f] font-semibold text-lg mt-2"
        >
          {isProcessing ? "Processing..." : "Pay Now"}
        </button>
      </form>
    </Modal>
  );
};

export default CardPaymentModal;
