// <script src=".../synapsepay.js"> build: exposes window.SynapsePay.
import { SynapsePay } from "./index.js";

(window as unknown as { SynapsePay: typeof SynapsePay }).SynapsePay = SynapsePay;
