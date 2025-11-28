try {
  throw new Error("test");
} catch (e) {
  print(e.message);
}
