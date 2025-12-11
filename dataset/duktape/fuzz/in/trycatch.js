// Try-catch
try {
    throw new Error("test error");
} catch (e) {
    print(e.message);
} finally {
    print("cleanup");
}
