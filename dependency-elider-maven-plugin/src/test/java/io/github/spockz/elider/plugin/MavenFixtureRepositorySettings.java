/* WHY: Gives nested Maven fixtures a deterministic file mirror.
 * It avoids copying dependency caches. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

/** Writes settings that resolve dependencies through a read-only local-file mirror. */
final class MavenFixtureRepositorySettings {
  private MavenFixtureRepositorySettings() {
    throw new AssertionError("No instances");
  }

  /* package */ static Path write(final Path evidenceDirectory, final String repositoryUri)
      throws IOException, XMLStreamException {
    final Path settings = evidenceDirectory.resolve("settings.xml");
    try (OutputStream output = Files.newOutputStream(settings)) {
      final XMLStreamWriter xml =
          XMLOutputFactory.newFactory().createXMLStreamWriter(output, "UTF-8");
      try {
        xml.writeStartDocument("UTF-8", "1.0");
        xml.writeStartElement("settings");
        xml.writeDefaultNamespace("http://maven.apache.org/SETTINGS/1.2.0");
        xml.writeNamespace("xsi", XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI);
        xml.writeAttribute(
            "xsi",
            XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI,
            "schemaLocation",
            "http://maven.apache.org/SETTINGS/1.2.0 "
                + "https://maven.apache.org/xsd/settings-1.2.0.xsd");
        writeCachedRepositoryMirror(xml, repositoryUri);
        writeRepositoryProfile(xml, repositoryUri);
        xml.writeEndElement();
        xml.writeEndDocument();
      } finally {
        xml.close();
      }
    }
    return settings;
  }

  private static void writeCachedRepositoryMirror(
      final XMLStreamWriter xml, final String repositoryUri) throws XMLStreamException {
    xml.writeStartElement("mirrors");
    xml.writeStartElement("mirror");
    writeTextElement(xml, "id", "cached-local-mirror");
    writeTextElement(xml, "mirrorOf", "*");
    writeTextElement(xml, "url", repositoryUri);
    xml.writeEndElement();
    xml.writeEndElement();
  }

  private static void writeRepositoryProfile(final XMLStreamWriter xml, final String repositoryUri)
      throws XMLStreamException {
    xml.writeStartElement("profiles");
    xml.writeStartElement("profile");
    writeTextElement(xml, "id", "cached-local-repository");
    xml.writeStartElement("repositories");
    writeRepository(xml, "repository", "cached-local-repository", repositoryUri);
    xml.writeEndElement();
    xml.writeStartElement("pluginRepositories");
    writeRepository(xml, "pluginRepository", "cached-local-plugins", repositoryUri);
    xml.writeEndElement();
    xml.writeEndElement();
    xml.writeEndElement();
    xml.writeStartElement("activeProfiles");
    writeTextElement(xml, "activeProfile", "cached-local-repository");
    xml.writeEndElement();
  }

  private static void writeRepository(
      final XMLStreamWriter xml,
      final String element,
      final String identifier,
      final String repositoryUri)
      throws XMLStreamException {
    xml.writeStartElement(element);
    writeTextElement(xml, "id", identifier);
    writeTextElement(xml, "url", repositoryUri);
    xml.writeEndElement();
  }

  /* package */ static void writeTextElement(
      final XMLStreamWriter xml, final String name, final String value) throws XMLStreamException {
    xml.writeStartElement(name);
    xml.writeCharacters(value);
    xml.writeEndElement();
  }
}
