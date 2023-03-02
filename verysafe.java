// Do some very unsafe things to assess Snyk vs. Checkmarx

import java.util.Scanner;
import java.net.http.*;
import java.nio.file.Files;
import java.io.*;
import java.sql.*;
import java.util.regex.*;
import java.util.Random;


class Main {
  public static void main(String[] args) {
    Scanner scnr = new Scanner(System.in);

    // Command injection from user input
    String input = scnr.nextLine();
    ProcessBuilder processBuilder = new ProcessBuilder();
    processBuilder.command(input);

    // Command argument injection
    processBuilder.command(args);

    // The following stored command defects are also path traversal defects

    // Stored command injection
    String filePath = scnr.nextLine();
    String contents = Files.readString(path, Charset.defaultCharset());
    processBuilder.command(contents);

    // Stored command argument injection
    contents = Files.readString(args[0], Charset.defaultCharset());
    processBuilder.command(contents);

    // Try to make it think we've sanitized input; should flag a warning
    input = scnr.nextLine();
    String sanitized = Sanitizer.sanitize(input);
    processBuilder.command(sanitized);

    // HTTP connection
    Connectioner.sendRequest("http://example.com");

    // SSRF
    input = scnr.nextLine();
    Connectioner.sendRequest(input);

    // Hardcoded secret
    String mySecret = "ARsoitenarnNNEENSNOONSIET";

    // Secret in connection string
    // Probably should also complain about unclosed resource
    DBTest.connect("jdbc:postgresql://myUser:aETNARIOETNntntne43@example.com:5432/testdb");

    // Connection string injection
    input = scnr.nextLine();
    c = DBTest.connect(input);

    // SQL injection
    input = scnr.nextLine();
    Statement stmt = c.createStatement();
    stmt.executeUpdate(input);
    stmt.close();

    c.close();

    // OS access violation/unsafe file delete
    input = scnr.nextLine();
    File file = new File(input);
    file.delete();

    // Deserialization of untrusted data
    // https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
    InputStream is = request.getInputStream();
    ObjectInputStream ois = new ObjectInputStream(is);
    
    // Unsafe deserialization
    input = scnr.nextLine();
    Object object = Deserializer.deserialize(input.getBytes());

    // Unsafe reflection
    String objectClassName = object.getClass().getSimpleName();
    Class cmdClass = Class.forName(objectClassName + "Command");
    Doer cmdObject = (Doer) cmdClass.newInstance();
    cmdObject.doSomething();

    // ReDoS - Snyk doesn't complain about any of these "evil" patterns
    String patterns[] = { "(a+)+$", "([a-zA-Z]+)*$", "(a|aa)+$", "(a|a?)+$", "(.*a){12}$" };
    for (String pStr : patterns) {
      Pattern pattern = Pattern.compile(pStr, Pattern.CASE_INSENSITIVE);
      Matcher matcher = pattern.matcher("aaaaaaaaaaaaaaaaaaaaaaaaaaa!");
      boolean matchFound = matcher.find();
    }

    // Try one explicitly; Snyk still doesn't complain
    Pattern pattern = Pattern.compile("(a+)+$", Pattern.CASE_INSENSITIVE);
    Matcher matcher = pattern.matcher("aaaaaaaaaaaaaaaaaaaaaaaaaaa!");
    boolean matchFound = matcher.find();

    // ReDoS for user input
    input = scnr.readLine();
    pattern = Pattern.compile("");
    matcher = pattern.matcher("the quick brown fox jumps over the lazy dog");
    matchFound = matcher.find();

    // Same seed in PRNG
    Random rand = new Random(4);  // Rolled by fair die; guaranteed to be random
    int totallyRandomISwear = random.nextInt(10);

    // Use of native language
    nativeIO = new NativeCode();
    int result = nativeIO.callNative("this obviously does nothing");
  }
}

class NativeCode {
  private native int nativeIO (char [] input);

  static {
    System.loadLibrary("NativeFramework");
  }

  public int callNative(String nInput) {
    char[] input = nInput.toCharArray();
    int result = nativeIO(input);
    return result;
  }
}

public interface Doer {
  public void doSomething();
}

class Deserializer {
  public static Object deserialize(byte[] buffer) throws IOException, ClassNotFoundException {
    Object ret = null;
    try (ByteArrayInputStream bais = new ByteArrayInputStream(buffer)) {
      try (ObjectInputStream ois = new ObjectInputStream(bais)) {
        ret = ois.readObject();
      }
    }
    return ret;
  }
}

class DBTest {
  public static Connection connect(String uri) {
    Connection c = null;
    try {
      Class.forName("org.postgresql.Driver");
      c = DriverManager.getConnection(uri, "postgres", "123");
      return c;
    } catch (Exception e) {
      System.out.println("Error, naturally");
      return null;
    }
  }
}

class Connectioner {
  public static void sendRequest(String url) {
    var client = HttpClient.newHttpClient();
    var request = HttpRequest.newBuilder(URI.create(url)).header("accept", "application/json").build();
    var response = client.send(request, new JsonBodyHandler<>(APOD.class));
    System.out.println(response.body().get().title);
  }
}

// A phony sanitizer
class Sanitizer {
  public static String sanitize(String input) {
    return input;
  }
}