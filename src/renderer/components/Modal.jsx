import React from 'react';
import ReactDOM from 'react-dom';

export default function Modal({ open, onClose, children }) {
  if (!open) return null;
  return ReactDOM.createPortal(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>,
    document.body
  );
}
